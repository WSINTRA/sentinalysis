//! Security-headers middleware: hardening headers on every response,
//! including a CSP that blocks inline scripts (`script-src 'self'`).

use std::future::{Ready, ready};
use std::sync::Arc;

use actix_web::Error;
use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderName, HeaderValue};
use futures::future::LocalBoxFuture;

/// The CSP applied to every response. `'unsafe-inline'` on `style-src` is
/// required by Mantine's runtime style injection; `script-src 'self'` is
/// the load-bearing XSS mitigation.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; \
     base-uri 'self'; form-action 'self'";

const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("Content-Security-Policy", CONTENT_SECURITY_POLICY),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
];

/// Middleware applying [`SECURITY_HEADERS`] to every response.
#[derive(Default, Clone, Copy)]
pub struct SecurityHeaders;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = SecurityHeadersMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddleware {
            service: Arc::new(service),
        }))
    }
}

pub struct SecurityHeadersMiddleware<S> {
    service: Arc<S>,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddleware<S>
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
        Box::pin(async move {
            let mut response = service.call(request).await?;
            for (name, value) in SECURITY_HEADERS {
                let name = HeaderName::from_bytes(name.as_bytes()).expect("valid header name");
                let value = HeaderValue::from_str(value).expect("valid header value");
                response.headers_mut().insert(name, value);
            }
            Ok(response.map_into_left_body())
        })
    }
}
