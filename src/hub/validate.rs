//! Shared input validation for every hub ingestion path (gRPC + REST).
//!
//! Validation happens in Rust before any DB write and is mirrored by
//! Postgres `CHECK` constraints as defense in depth. Rejections are always
//! explicit (a reason is returned); data is never silently dropped.

use chrono::{DateTime, Utc};
use regex::Regex;
use std::sync::OnceLock;

/// Maximum serialized payload size for a single app event (4 KiB).
pub const MAX_PAYLOAD_BYTES: usize = 4 * 1024;
/// Maximum characters for an event/user/app/container name.
pub const MAX_EVENT_TYPE_LEN: usize = 64;
pub const MAX_USER_ID_LEN: usize = 128;
pub const MAX_CONTAINER_LEN: usize = 64;
/// Maximum `message` length for an agent log line (truncated server-side).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
/// Maximum events accepted per `POST /v1/events` request.
pub const MAX_EVENTS_PER_REQUEST: usize = 500;
/// Maximum log lines accepted per `SendLogs` request.
pub const MAX_LINES_PER_REQUEST: usize = 1000;
/// Maximum characters for a request path / client IP / noise reason.
pub const MAX_PATH_LEN: usize = 2048;
/// Accepted `level` values for forwarded parsed entries (the agent's
/// `LogLevel::as_str` vocabulary — validation only, no classification).
pub const LEVELS: [&str; 6] = ["debug", "info", "warn", "error", "critical", "security"];
/// Accepted `threat_level` values (the agent's `ThreatLevel::as_str`).
pub const THREAT_LEVELS: [&str; 5] = ["none", "low", "medium", "high", "critical"];
/// Maximum threat categories per entry.
pub const MAX_THREAT_CATEGORIES: usize = 16;
/// Page size bounds for list endpoints.
pub const MIN_LIMIT: i64 = 1;
pub const MAX_LIMIT: i64 = 200;
pub const DEFAULT_LIMIT: i64 = 50;
pub const MAX_OFFSET: i64 = 100_000;
/// Timestamp acceptance window: reject far-future (clock skew) and
/// ancient (stale replay / garbage) timestamps.
pub const MAX_FUTURE_SKEW_SECS: i64 = 5 * 60;
pub const MAX_PAST_AGE_DAYS: i64 = 30;

fn event_type_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9_.:-]{1,64}$").expect("valid regex"))
}

fn app_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9._-]{1,64}$").expect("valid regex"))
}

fn container_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9._-]{1,64}$").expect("valid regex"))
}

/// Checks `event_type` against the charset/length rule and, when provided,
/// the configured allowlist.
pub fn event_type(value: &str, allowlist: Option<&[String]>) -> Result<(), String> {
    if !event_type_re().is_match(value) {
        return Err(format!(
            "event_type '{value}' must match [a-z0-9_.:-] and be 1..={MAX_EVENT_TYPE_LEN} chars"
        ));
    }
    if let Some(list) = allowlist
        && !list.is_empty()
        && !list.iter().any(|allowed| allowed == value)
    {
        return Err(format!(
            "event_type '{value}' is not in the configured allowlist"
        ));
    }
    Ok(())
}

/// Checks an app name (only reached via tests today: on the wire the
/// app name always comes from the key row, which was validated at
/// key-creation time).
pub fn app_name(value: &str) -> Result<(), String> {
    if !app_name_re().is_match(value) {
        return Err(format!(
            "app_name '{value}' must match [a-z0-9._-] and be 1..=64 chars"
        ));
    }
    Ok(())
}

/// Checks a user identifier: length cap, no control characters.
pub fn user_id(value: &str) -> Result<(), String> {
    if value.len() > MAX_USER_ID_LEN {
        return Err(format!("user_id exceeds {MAX_USER_ID_LEN} chars"));
    }
    if value.chars().any(char::is_control) {
        return Err("user_id contains control characters".to_string());
    }
    Ok(())
}

/// Checks a Docker container name.
pub fn container(value: &str) -> Result<(), String> {
    if !container_re().is_match(value) {
        return Err(format!(
            "container '{value}' must match [A-Za-z0-9._-] and be 1..=64 chars"
        ));
    }
    Ok(())
}

/// Checks a log stream name.
pub fn stream(value: &str) -> Result<(), String> {
    if value != "stdout" && value != "stderr" {
        return Err(format!(
            "stream must be 'stdout' or 'stderr', got '{value}'"
        ));
    }
    Ok(())
}

/// Checks a service name coming from an agent (vhost or log file name).
pub fn service_name(value: &str) -> Result<(), String> {
    if !container_re().is_match(value) {
        return Err(format!(
            "service_name '{value}' must match [A-Za-z0-9._-] and be 1..=64 chars"
        ));
    }
    Ok(())
}

/// Checks a service `unit_type` token (e.g. `nginx-vhost`).
pub fn unit_type(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_EVENT_TYPE_LEN
        || !value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "unit_type '{value}' must be lowercase [a-z0-9-], 1..={MAX_EVENT_TYPE_LEN} chars"
        ));
    }
    Ok(())
}

/// Checks a stored `level` token against the agent vocabulary.
pub fn level(value: &str) -> Result<(), String> {
    if !LEVELS.contains(&value) {
        return Err(format!("level '{value}' not in {LEVELS:?}"));
    }
    Ok(())
}

/// Checks a stored `threat_level` token against the agent vocabulary.
pub fn threat_level(value: &str) -> Result<(), String> {
    if !THREAT_LEVELS.contains(&value) {
        return Err(format!("threat_level '{value}' not in {THREAT_LEVELS:?}"));
    }
    Ok(())
}

/// Checks threat categories: bounded count and safe tokens.
pub fn threat_categories(values: &[String]) -> Result<(), String> {
    if values.len() > MAX_THREAT_CATEGORIES {
        return Err("too many threat categories".to_string());
    }
    for value in values {
        if value.is_empty()
            || value.len() > MAX_EVENT_TYPE_LEN
            || !value
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(format!(
                "threat category '{value}' must be lowercase [a-z0-9-]"
            ));
        }
    }
    Ok(())
}

/// Checks a client IP string.
pub fn client_ip(value: &str) -> Result<(), String> {
    if value.parse::<std::net::IpAddr>().is_ok() {
        Ok(())
    } else {
        Err(format!("client_ip '{value}' is not an IP address"))
    }
}

/// Checks a request path: bounded length, no control characters.
pub fn request_path(value: &str) -> Result<(), String> {
    if value.len() > MAX_PATH_LEN {
        return Err(format!("request_path exceeds {MAX_PATH_LEN} chars"));
    }
    if value.chars().any(char::is_control) {
        return Err("request_path contains control characters".to_string());
    }
    Ok(())
}

/// Checks an optional short free-text field (noise reason, vhost).
pub fn short_text(value: &str, name: &str) -> Result<(), String> {
    if value.len() > MAX_USER_ID_LEN {
        return Err(format!("{name} exceeds {MAX_USER_ID_LEN} chars"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{name} contains control characters"));
    }
    Ok(())
}

/// Validates an event timestamp against the acceptance window
/// (no more than 5 minutes in the future, no more than 30 days old).
pub fn timestamp(ts: DateTime<Utc>, now: DateTime<Utc>) -> Result<(), String> {
    let skew = (ts - now).num_seconds();
    if skew > MAX_FUTURE_SKEW_SECS {
        return Err(format!(
            "timestamp is {skew}s in the future (max {MAX_FUTURE_SKEW_SECS}s)"
        ));
    }
    let age = -(ts - now).num_seconds();
    let max_age_secs = MAX_PAST_AGE_DAYS * 24 * 3600;
    if age > max_age_secs {
        return Err(format!(
            "timestamp is {age}s old (max {max_age_secs}s = {MAX_PAST_AGE_DAYS} days)"
        ));
    }
    Ok(())
}

/// Normalizes an agent log message: strips the trailing newline, truncates
/// to `MAX_MESSAGE_BYTES` at a char boundary, and marks truncation.
#[must_use]
pub fn sanitize_message(raw: &str) -> String {
    let trimmed = raw.strip_suffix('\n').unwrap_or(raw);
    if trimmed.len() <= MAX_MESSAGE_BYTES {
        return trimmed.to_string();
    }
    // Truncate on a UTF-8 char boundary: walk back from the byte cap until
    // the slice is valid.
    let mut end = MAX_MESSAGE_BYTES;
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &trimmed[..end])
}

/// Validates a page size (`limit`) for list endpoints.
pub fn limit(value: i64) -> Result<i64, String> {
    if !(MIN_LIMIT..=MAX_LIMIT).contains(&value) {
        return Err(format!("limit must be between {MIN_LIMIT} and {MAX_LIMIT}"));
    }
    Ok(value)
}

/// Validates a pagination offset.
pub fn offset(value: i64) -> Result<i64, String> {
    if !(0..=MAX_OFFSET).contains(&value) {
        return Err(format!("offset must be between 0 and {MAX_OFFSET}"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 9, 12, 0, 0).unwrap()
    }

    // ---- event_type ----

    #[test]
    fn event_type_accepts_valid() {
        for value in [
            "user_login",
            "cart_add",
            "checkout_start",
            "a",
            "type.with.dots",
            "x:y",
        ] {
            assert!(event_type(value, None).is_ok(), "{value}");
        }
    }

    #[test]
    fn event_type_rejects_xss_and_injection() {
        for value in [
            "<script>alert(1)</script>",
            "user'; DROP TABLE app_events;--",
            "user_login\n",
            "USER_LOGIN",
            "with space",
            "",
            "ümlaut",
            "emoji🎉",
        ] {
            assert!(event_type(value, None).is_err(), "must reject '{value}'");
        }
    }

    #[test]
    fn event_type_rejects_overlong() {
        let value = "a".repeat(65);
        assert!(event_type(&value, None).is_err());
        let value_ok = "a".repeat(64);
        assert!(event_type(&value_ok, None).is_ok());
    }

    #[test]
    fn event_type_allowlist_enforced_when_nonempty() {
        let allow = vec!["user_login".to_string()];
        assert!(event_type("user_login", Some(&allow)).is_ok());
        assert!(event_type("cart_add", Some(&allow)).is_err());
        // Empty allowlist = no restriction beyond charset.
        assert!(event_type("cart_add", Some(&[])).is_ok());
    }

    // ---- app_name / user_id / container / stream ----

    #[test]
    fn app_name_valid() {
        assert!(app_name("globalware").is_ok());
        assert!(app_name("app.v2-beta").is_ok());
        assert!(app_name("").is_err());
        assert!(app_name("App").is_err());
        assert!(app_name("a; drop").is_err());
    }

    #[test]
    fn user_id_rules() {
        assert!(user_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(user_id(&"x".repeat(128)).is_ok());
        assert!(user_id(&"x".repeat(129)).is_err());
        assert!(user_id("bad\u{0}id").is_err());
        assert!(user_id("bad\nid").is_err());
    }

    #[test]
    fn container_rules() {
        assert!(container("app").is_ok());
        assert!(container("my-app_1.2").is_ok());
        assert!(container("../etc/passwd").is_err());
        assert!(container("a b").is_err());
        assert!(container(&"x".repeat(65)).is_err());
    }

    #[test]
    fn stream_rules() {
        assert!(stream("stdout").is_ok());
        assert!(stream("stderr").is_ok());
        assert!(stream("STDOUT").is_err());
        assert!(stream("").is_err());
        assert!(stream("x").is_err());
    }

    // ---- timestamp ----

    #[test]
    fn timestamp_accepts_recent() {
        let past = now() - chrono::Duration::hours(1);
        assert!(timestamp(past, now()).is_ok());
        let future = now() + chrono::Duration::minutes(4);
        assert!(timestamp(future, now()).is_ok());
        assert!(timestamp(now(), now()).is_ok());
    }

    #[test]
    fn timestamp_rejects_far_future() {
        let future = now() + chrono::Duration::hours(2);
        assert!(timestamp(future, now()).is_err());
        let year = now() + chrono::Duration::days(365);
        assert!(timestamp(year, now()).is_err());
    }

    #[test]
    fn timestamp_rejects_stale() {
        let old = now() - chrono::Duration::days(31);
        assert!(timestamp(old, now()).is_err());
        let ok = now() - chrono::Duration::days(29);
        assert!(timestamp(ok, now()).is_ok());
    }

    // ---- message sanitization ----

    #[test]
    fn sanitize_strips_trailing_newline() {
        assert_eq!(sanitize_message("hello\n"), "hello");
        assert_eq!(sanitize_message("hello"), "hello");
    }

    #[test]
    fn sanitize_short_message_unchanged() {
        assert_eq!(sanitize_message("ok"), "ok");
    }

    #[test]
    fn sanitize_truncates_overlong_ascii() {
        let long = "x".repeat(MAX_MESSAGE_BYTES + 100);
        let out = sanitize_message(&long);
        // Truncated body + ellipsis marker.
        assert_eq!(out.len(), MAX_MESSAGE_BYTES + '…'.len_utf8());
        assert!(out.ends_with('…'));
    }

    #[test]
    fn sanitize_truncates_on_char_boundary() {
        // Fill with multi-byte chars so the byte cap lands mid-char.
        let long = "ü".repeat(MAX_MESSAGE_BYTES);
        let out = sanitize_message(&long);
        assert!(out.ends_with('…'));
        assert!(out.chars().all(|c| c == 'ü' || c == '…'));
    }

    // ---- parsed-entry field validators ----

    #[test]
    fn service_name_rules() {
        assert!(service_name("api.example.com").is_ok());
        assert!(service_name("auth.log").is_ok());
        assert!(service_name("").is_err());
        assert!(service_name("bad name").is_err());
        assert!(service_name("../etc").is_err());
        assert!(service_name(&"x".repeat(65)).is_err());
    }

    #[test]
    fn unit_type_rules() {
        assert!(unit_type("nginx-vhost").is_ok());
        assert!(unit_type("system-log").is_ok());
        assert!(unit_type("Docker").is_err());
        assert!(unit_type("has space").is_err());
        assert!(unit_type("").is_err());
    }

    #[test]
    fn level_and_threat_vocabularies() {
        assert!(level("security").is_ok());
        assert!(level("info").is_ok());
        assert!(level("SECURITY").is_err());
        assert!(level("bogus").is_err());
        assert!(threat_level("none").is_ok());
        assert!(threat_level("critical").is_ok());
        assert!(threat_level("extreme").is_err());
    }

    #[test]
    fn threat_categories_rules() {
        assert!(threat_categories(&["sql-injection".into(), "xss".into()]).is_ok());
        assert!(threat_categories(&[]).is_ok());
        assert!(threat_categories(&["SQLi".into()]).is_err());
        assert!(threat_categories(&["ok".repeat(70)]).is_err());
        let many = vec!["xss".to_string(); MAX_THREAT_CATEGORIES + 1];
        assert!(threat_categories(&many).is_err());
    }

    #[test]
    fn client_ip_and_path_rules() {
        assert!(client_ip("203.0.113.9").is_ok());
        assert!(client_ip("::1").is_ok());
        assert!(client_ip("not-an-ip").is_err());
        assert!(request_path("/users?id=1").is_ok());
        assert!(request_path(&"a".repeat(MAX_PATH_LEN + 1)).is_err());
        assert!(request_path("bad\npath").is_err());
    }

    #[test]
    fn short_text_rules() {
        assert!(short_text("health check", "noise_reason").is_ok());
        assert!(short_text(&"x".repeat(MAX_USER_ID_LEN + 1), "x").is_err());
        assert!(short_text("bad\0", "x").is_err());
    }

    // ---- pagination ----

    #[test]
    fn limit_bounds() {
        assert_eq!(limit(1).unwrap(), 1);
        assert_eq!(limit(50).unwrap(), 50);
        assert_eq!(limit(200).unwrap(), 200);
        assert!(limit(0).is_err());
        assert!(limit(-1).is_err());
        assert!(limit(201).is_err());
    }

    #[test]
    fn offset_bounds() {
        assert_eq!(offset(0).unwrap(), 0);
        assert_eq!(offset(100_000).unwrap(), 100_000);
        assert!(offset(-1).is_err());
        assert!(offset(100_001).is_err());
    }
}
