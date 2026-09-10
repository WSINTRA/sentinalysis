//! Actix middleware + helpers for `X-API-KEY` authentication on every REST
//! route. `GET /api/v1/health` is exempted by registering it outside the
//! guarded scope.

use std::future::{Ready, ready};
use std::sync::Arc;

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::StatusCode;
use actix_web::{Error, HttpMessage, HttpRequest, HttpResponse};
use futures::future::LocalBoxFuture;
use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;

use crate::hub::auth::{AuthError, AuthService, Principal};

/// Canonical auth header (also accepted: `Authorization: Bearer`).
pub const API_KEY_HEADER: &str = "X-API-KEY";

/// Extracts the raw key from the request headers, trying `X-API-KEY` then
/// `Authorization: Bearer`.
#[must_use]
pub fn extract_key(request: &HttpRequest) -> Option<String> {
    if let Some(value) = request
        .headers()
        .get(API_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        return Some(value.to_string());
    }
    request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(std::string::ToString::to_string)
}

/// The client IP as seen by the hub.
#[must_use]
pub fn client_ip(request: &HttpRequest) -> String {
    request
        .peer_addr()
        .map_or_else(|| "unknown".into(), |addr| addr.ip().to_string())
}

/// Fetches the authenticated [`Principal`] inserted by the middleware.
///
/// # Errors
/// 401 when the middleware did not run.
pub fn principal(request: &HttpRequest) -> Result<Principal, Error> {
    request
        .extensions()
        .get::<Principal>()
        .cloned()
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("authentication required"))
}

/// Actix extractor for the authenticated principal (set by [`KeyAuth`]).
pub struct PrincipalExtractor(pub Principal);

impl actix_web::FromRequest for PrincipalExtractor {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(request: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        ready(principal(request).map(PrincipalExtractor))
    }
}

/// Per-key rate limiter for the events ingestion endpoint.
pub struct EventRateLimiter {
    inner: RateLimiter<String, DashMapStateStore<String>, DefaultClock>,
}

impl EventRateLimiter {
    #[must_use]
    pub fn new(per_minute: u32) -> Self {
        Self {
            inner: RateLimiter::keyed(
                Quota::per_minute(NonZeroU32::new(per_minute).expect("non-zero"))
                    .allow_burst(NonZeroU32::new(per_minute).expect("non-zero")),
            ),
        }
    }

    /// Returns `true` when the request is within budget.
    #[must_use]
    pub fn allow(&self, key_id: &str) -> bool {
        self.inner.check_key(&key_id.to_string()).is_ok()
    }
}

/// Authentication middleware: resolves the `X-API-KEY`, applies the per-IP
/// attempt budget, verifies the key, and inserts the [`Principal`] into
/// request extensions.
#[derive(Clone)]
pub struct KeyAuth {
    auth: Arc<AuthService>,
}

impl KeyAuth {
    #[must_use]
    pub fn new(auth: Arc<AuthService>) -> Self {
        Self { auth }
    }
}

impl<S, B> Transform<S, ServiceRequest> for KeyAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = KeyAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(KeyAuthMiddleware {
            service: Arc::new(service),
            auth: self.auth.clone(),
        }))
    }
}

pub struct KeyAuthMiddleware<S> {
    service: Arc<S>,
    auth: Arc<AuthService>,
}

impl<S, B> Service<ServiceRequest> for KeyAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &self,
        ctx: &mut core::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let auth = self.auth.clone();
        Box::pin(async move {
            let ip = client_ip(request.request());

            // Budget applies before any key parsing (CPU-exhaustion guard).
            if let Err(e) = auth.check_ip_budget(&ip) {
                return Ok(reject(request, e, StatusCode::TOO_MANY_REQUESTS));
            }

            let Some(raw_key) = extract_key(request.request()) else {
                return Ok(reject(
                    request,
                    AuthError::Malformed,
                    StatusCode::UNAUTHORIZED,
                ));
            };

            match auth.authenticate(&raw_key).await {
                Ok(principal) => {
                    request.extensions_mut().insert(principal);
                    let response = service.call(request).await?;
                    Ok(response.map_into_left_body())
                }
                Err(e) => {
                    let status = match &e {
                        AuthError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
                        AuthError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
                        AuthError::Malformed | AuthError::UnknownKey | AuthError::BadSignature => {
                            StatusCode::UNAUTHORIZED
                        }
                    };
                    tracing::warn!(ip, "REST auth failure: {e}");
                    Ok(reject(request, e, status))
                }
            }
        })
    }
}

/// Converts the request into a JSON error response with the right status.
fn reject<B>(
    request: ServiceRequest,
    error: AuthError,
    status: StatusCode,
) -> ServiceResponse<EitherBody<B>> {
    let message = match error {
        AuthError::Malformed => "malformed API key".to_string(),
        AuthError::UnknownKey => "unknown API key".to_string(),
        AuthError::BadSignature => "invalid API key".to_string(),
        AuthError::RateLimited => "too many authentication attempts".to_string(),
        AuthError::Storage(message) => {
            format!("authentication storage failure: {message}")
        }
    };
    let (http_request, _) = request.into_parts();
    let response = HttpResponse::build(status).json(serde_json::json!({ "error": message }));
    ServiceResponse::new(http_request, response.map_into_boxed_body()).map_into_right_body()
}
