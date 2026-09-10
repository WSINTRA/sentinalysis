//! API-key authentication for every hub path (gRPC + REST).
//!
//! Verification path, cheapest steps first, so unauthenticated traffic
//! cannot burn CPU:
//!
//! 1. per-IP attempt rate limit (governor, 20/min) — before any hashing
//! 2. format check `snt_<key_id>_<secret>` — rejects garbage in microseconds
//! 3. cache lookup by `key_id` (60s TTL) — steady-state cost
//! 4. indexed DB lookup by `key_id` — one row, no scan
//! 5. argon2 verify — exactly one, only on cache miss
//!
//! The resolved [`Principal`] carries the trusted identity from the key
//! row: nothing about identity ever comes from the wire.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::{Argon2, PasswordHasher};
use base64::Engine;
use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};
use rand::RngCore;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::num::NonZeroU32;
use std::sync::OnceLock;
use tokio::sync::RwLock;

use crate::db::repositories::api_key_repo::{ApiKeyRepository, ApiKeyRow};
use crate::error::SentinelError;

/// API-key wire format: `snt_<8 hex>_<43 base64url>`.
pub const KEY_PREFIX: &str = "snt_";
const KEY_ID_LEN: usize = 8;
const SECRET_LEN: usize = 43;

/// Cache capacity; keys beyond this evict oldest (FIFO — fine at this scale).
const CACHE_MAX_ENTRIES: usize = 1000;
/// How long a verified principal is trusted without re-running argon2.
const CACHE_TTL: Duration = Duration::new(60, 0);
/// Per-IP authentication attempt budget (applied before any hashing).
const MAX_AUTH_ATTEMPTS_PER_MINUTE: u32 = 20;

fn key_format_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(
            r"^{KEY_PREFIX}[0-9a-f]{{{KEY_ID_LEN}}}_[A-Za-z0-9_-]{{{SECRET_LEN}}}$"
        ))
        .expect("valid regex")
    })
}

/// Permissions a key can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    IngestMetrics,
    IngestLogs,
    IngestEvents,
    ReadDashboard,
}

impl Permission {
    /// The `permissions[]` wire value stored in `api_keys`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IngestMetrics => "ingest:metrics",
            Self::IngestLogs => "ingest:logs",
            Self::IngestEvents => "ingest:events",
            Self::ReadDashboard => "read:dashboard",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ingest:metrics" => Some(Self::IngestMetrics),
            "ingest:logs" => Some(Self::IngestLogs),
            "ingest:events" => Some(Self::IngestEvents),
            "read:dashboard" => Some(Self::ReadDashboard),
            _ => None,
        }
    }
}

/// The authenticated caller: permissions plus the trusted identity from the
/// key row. Client-supplied identity fields are never part of this.
#[derive(Debug, Clone)]
pub struct Principal {
    pub key_id: String,
    pub permissions: HashSet<Permission>,
    /// Present only for agent keys.
    pub agent_id: Option<String>,
    /// Present only for agent keys (trusted hostname, set at key creation).
    pub hostname: Option<String>,
    /// Present only for app keys.
    pub app_name: Option<String>,
}

impl Principal {
    /// Requires a permission or fails with a descriptive auth error.
    ///
    /// # Errors
    /// `AuthError` when the permission is missing.
    pub fn require(&self, permission: Permission) -> Result<(), SentinelError> {
        if self.permissions.contains(&permission) {
            Ok(())
        } else {
            Err(SentinelError::AuthError(format!(
                "key lacks required permission '{}'",
                permission.as_str()
            )))
        }
    }
}

/// Authentication failure kinds, mapped to HTTP/gRPC status by the callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Header missing or not matching the `snt_...` format.
    Malformed,
    /// Format-valid but no active key with that `key_id`.
    UnknownKey,
    /// Key found but the secret did not verify.
    BadSignature,
    /// Per-IP attempt budget exhausted (enforced before argon2).
    RateLimited,
    /// Database failure while authenticating.
    Storage(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed API key"),
            Self::UnknownKey => write!(f, "unknown API key"),
            Self::BadSignature => write!(f, "invalid API key"),
            Self::RateLimited => write!(f, "too many authentication attempts"),
            Self::Storage(msg) => write!(f, "authentication storage failure: {msg}"),
        }
    }
}

struct CacheEntry {
    principal: Principal,
    inserted_at: Instant,
}

/// A small bounded FIFO cache: at this deployment's scale (a handful of
/// keys) ordered-map eviction is sufficient and dependency-free.
struct VerifiedCache {
    map: std::collections::HashMap<String, CacheEntry>,
    order: std::collections::VecDeque<String>,
}

impl VerifiedCache {
    fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    fn get(&self, key_id: &str) -> Option<&Principal> {
        let entry = self.map.get(key_id)?;
        if entry.inserted_at.elapsed() > CACHE_TTL {
            return None; // expired; cleaned up on insert
        }
        Some(&entry.principal)
    }

    fn insert(&mut self, key_id: String, principal: Principal) {
        if !self.order.contains(&key_id) {
            self.order.push_back(key_id.clone());
        }
        self.map.insert(
            key_id,
            CacheEntry {
                principal,
                inserted_at: Instant::now(),
            },
        );
        // Purge expired entries opportunistically, then enforce capacity.
        self.order.retain(|k| {
            let keep = self
                .map
                .get(k)
                .is_some_and(|e| e.inserted_at.elapsed() <= CACHE_TTL);
            if !keep {
                self.map.remove(k);
            }
            keep
        });
        while self.order.len() > CACHE_MAX_ENTRIES {
            if let Some(evicted) = self.order.pop_front() {
                self.map.remove(&evicted);
            }
        }
    }

    fn invalidate(&mut self, key_id: &str) {
        self.map.remove(key_id);
        self.order.retain(|k| k != key_id);
    }
}

/// The authentication service. Cheap to clone; shares cache and limiter.
#[derive(Clone)]
pub struct AuthService {
    repo: ApiKeyRepository,
    cache: Arc<RwLock<VerifiedCache>>,
    ip_limiter: Arc<RateLimiter<String, DashMapStateStore<String>, DefaultClock>>,
}

impl AuthService {
    #[must_use]
    pub fn new(repo: ApiKeyRepository) -> Self {
        Self {
            repo,
            cache: Arc::new(RwLock::new(VerifiedCache::new())),
            ip_limiter: Arc::new(RateLimiter::keyed(
                Quota::per_minute(NonZeroU32::new(MAX_AUTH_ATTEMPTS_PER_MINUTE).expect("non-zero"))
                    .allow_burst(NonZeroU32::new(MAX_AUTH_ATTEMPTS_PER_MINUTE).expect("non-zero")),
            )),
        }
    }

    /// Removes a `key_id` from the verified cache so revocation takes
    /// effect immediately (called by the `hub-key revoke` path).
    pub async fn invalidate(&self, key_id: &str) {
        self.cache.write().await.invalidate(key_id);
    }

    /// Per-IP budget check; callers apply this **before** parsing the key.
    ///
    /// # Errors
    /// `AuthError::RateLimited` when the IP exceeded its budget.
    pub fn check_ip_budget(&self, ip: &str) -> Result<(), AuthError> {
        self.ip_limiter
            .check_key(&ip.to_string())
            .map_err(|_| AuthError::RateLimited)
    }

    /// Authenticates a raw key string.
    ///
    /// # Errors
    /// `AuthError` variants; storage failures wrap into `AuthError::Storage`.
    pub async fn authenticate(&self, raw_key: &str) -> Result<Principal, AuthError> {
        let key_id = parse_key_id(raw_key).ok_or(AuthError::Malformed)?;

        if let Some(principal) = self.cache.read().await.get(key_id) {
            return Ok(principal.clone());
        }

        let row = self
            .repo
            .find_active_by_key_id(key_id)
            .await
            .map_err(|e| AuthError::Storage(e.to_string()))?
            .ok_or(AuthError::UnknownKey)?;

        verify_hash(&row.hash, raw_key).map_err(|_| AuthError::BadSignature)?;

        let principal = principal_from_row(&row);
        self.cache
            .write()
            .await
            .insert(row.key_id.clone(), principal.clone());
        // Fire-and-forget usage stamping; failure is harmless.
        let repo = self.repo.clone();
        let id = row.id;
        tokio::spawn(async move {
            let _ = repo.touch_last_used(id).await;
        });

        Ok(principal)
    }
}

/// Extracts the `key_id` from a format-valid key.
#[must_use]
pub fn parse_key_id(raw_key: &str) -> Option<&str> {
    if !key_format_re().is_match(raw_key) {
        return None;
    }
    raw_key.get(KEY_PREFIX.len()..KEY_PREFIX.len() + KEY_ID_LEN)
}

/// Cheap pre-check for callers that want to reject garbage without
/// touching the limiter or DB.
#[must_use]
pub fn is_wellformed(raw_key: &str) -> bool {
    key_format_re().is_match(raw_key)
}

fn verify_hash(stored_hash: &str, raw_key: &str) -> Result<(), AuthError> {
    let parsed = PasswordHash::new(stored_hash)
        .map_err(|e| AuthError::Storage(format!("stored hash unparseable: {e}")))?;
    Argon2::default()
        .verify_password(raw_key.as_bytes(), &parsed)
        .map_err(|_| AuthError::BadSignature)
}

fn principal_from_row(row: &ApiKeyRow) -> Principal {
    let permissions = row
        .permissions
        .iter()
        .filter_map(|p| Permission::parse(p))
        .collect::<HashSet<_>>();
    Principal {
        key_id: row.key_id.clone(),
        permissions,
        agent_id: row.agent_id.clone(),
        hostname: row.hostname.clone(),
        app_name: row.app_name.clone(),
    }
}

/// Generates a new key: returns `(raw_key, key_id)`. The raw key is shown
/// exactly once; only its argon2 hash and the `key_id` are stored.
#[must_use]
pub fn generate_key() -> (String, String) {
    let mut secret_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_bytes);
    let digest = Sha256::digest(secret.as_bytes());
    let key_id = hex_encode(&digest[..4]);
    (format!("{KEY_PREFIX}{key_id}_{secret}"), key_id)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Hashes a raw key for storage (argon2id, default OWASP params).
///
/// # Errors
/// `SentinelError::Internal` on hash-generation failure (should not happen).
pub fn hash_key(raw_key: &str) -> Result<String, SentinelError> {
    use argon2::password_hash::SaltString;
    use argon2::password_hash::rand_core::OsRng as HashRng;
    let salt = SaltString::generate(&mut HashRng);
    let hash = Argon2::default()
        .hash_password(raw_key.as_bytes(), &salt)
        .map_err(|e| SentinelError::Internal(format!("argon2 failure: {e}")))?;
    Ok(hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- key format ----

    #[test]
    fn generated_key_is_wellformed_and_ids_match() {
        let (raw, key_id) = generate_key();
        assert!(is_wellformed(&raw), "{raw}");
        assert_eq!(parse_key_id(&raw), Some(key_id.as_str()));
        assert_eq!(key_id.len(), 8);
        assert!(raw.starts_with("snt_"));
    }

    #[test]
    fn generated_keys_are_unique() {
        let (a, _) = generate_key();
        let (b, _) = generate_key();
        assert_ne!(a, b);
    }

    #[test]
    fn malformed_keys_rejected_before_anything_expensive() {
        for bad in [
            "",
            "snt_",
            "snt_a1b2c3d4_",
            "snt_ZZZZZZZZ_x",
            "snt_a1b2c3d4_short",
            "bearer snt_a1b2c3d4_x",
            "snt_a1b2c3d4_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "snt_a1b2c3d4_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "snt_a1b2c3d4_xxx xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ] {
            assert_eq!(parse_key_id(bad), None, "must reject '{bad}'");
        }
    }

    // ---- permissions ----

    #[test]
    fn permission_strings_roundtrip() {
        for p in [
            Permission::IngestMetrics,
            Permission::IngestLogs,
            Permission::IngestEvents,
            Permission::ReadDashboard,
        ] {
            assert_eq!(Permission::parse(p.as_str()), Some(p));
        }
        assert_eq!(Permission::parse("bogus"), None);
    }

    #[test]
    fn principal_require_enforces() {
        let mut principal = Principal {
            key_id: "a1b2c3d4".into(),
            permissions: HashSet::from([Permission::IngestEvents]),
            agent_id: None,
            hostname: None,
            app_name: Some("app".into()),
        };
        assert!(principal.require(Permission::IngestEvents).is_ok());
        assert!(principal.require(Permission::ReadDashboard).is_err());
        principal.permissions.clear();
        assert!(principal.require(Permission::IngestEvents).is_err());
    }

    // ---- hashing ----

    #[test]
    fn hash_and_verify_roundtrip() {
        let (raw, _) = generate_key();
        let hash = hash_key(&raw).unwrap();
        assert!(verify_hash(&hash, &raw).is_ok());
        let (other, _) = generate_key();
        assert!(matches!(
            verify_hash(&hash, &other),
            Err(AuthError::BadSignature)
        ));
    }

    #[test]
    fn verify_rejects_unparseable_hash() {
        assert!(matches!(
            verify_hash("not-a-phc-hash", "whatever"),
            Err(AuthError::Storage(_))
        ));
    }

    // ---- IP budget ----

    #[tokio::test]
    async fn ip_budget_blocks_after_limit() {
        let pool = sqlx::PgPool::connect_lazy("postgresql://test:test@localhost/none").unwrap();
        let service = AuthService::new(ApiKeyRepository::new(pool));
        for _ in 0..MAX_AUTH_ATTEMPTS_PER_MINUTE {
            assert!(service.check_ip_budget("10.1.2.3").is_ok());
        }
        assert_eq!(
            service.check_ip_budget("10.1.2.3"),
            Err(AuthError::RateLimited)
        );
        // Other IPs are unaffected.
        assert!(service.check_ip_budget("10.1.2.4").is_ok());
    }
}
