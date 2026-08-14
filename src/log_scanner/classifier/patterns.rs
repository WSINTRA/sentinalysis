//! Data-driven threat pattern tables for the `Classifier`.
//!
//! Every substring-based detection rule lives here, grouped by
//! `ThreatCategory`. To add a new pattern, append a `PatternRule` to the
//! table — no code changes needed.
//!
//! Semantics: patterns are **literal substrings** (not regexes) and must
//! be written in **lowercase**, because all inputs are lowercased before
//! matching. The `PatternScope` of a rule decides where the pattern is
//! searched:
//! - `Text`: the lowercased `message + " " + raw` of the entry
//! - `Path`: the lowercased request path
//! - `TextAndPath`: either of the above
//! - `UserAgent`: the lowercased user agent
//! - `PathPrefix`: the request path, matched as equality or prefix
//!   (sensitive file paths may appear as whole paths or directory prefixes)

use super::ThreatCategory;

/// Where a pattern is searched for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternScope {
    Text,
    Path,
    TextAndPath,
    UserAgent,
    PathPrefix,
}

/// One literal-substring detection rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternRule {
    pub category: ThreatCategory,
    pub scope: PatternScope,
    pub pattern: &'static str,
}

const fn rule(category: ThreatCategory, scope: PatternScope, pattern: &'static str) -> PatternRule {
    PatternRule {
        category,
        scope,
        pattern,
    }
}

/// All substring detection rules, grouped by category.
///
/// The order is irrelevant: the classifier adds a category once any of its
/// rules matches.
pub const PATTERN_RULES: &[PatternRule] = &[
    // --- Command injection (shell metacharacters in text or path) ---
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        ";cat ",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        ";ls ",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        ";whoami",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        ";id ",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        ";rm ",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        "|grep",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        "|cat ",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        "`whoami`",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        "`id`",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        "$(wget",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        "$(curl",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        "$(cat ",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        ";wget ",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        ";curl ",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        ";nc ",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        ";bash ",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        ";sh ",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        ";python ",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        ";perl ",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        ";ruby ",
    ),
    rule(
        ThreatCategory::CommandInjection,
        PatternScope::TextAndPath,
        ";php ",
    ),
    // --- SQL injection ---
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "' or '",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "' or 1",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        " or 1=1",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        " or '1'='1",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "union select",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "union all select",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "drop table",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "drop database",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "insert into",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "delete from",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "update .* set",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "exec xp_",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "exec sp_",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "';--",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "'--",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "admin'--",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "1; drop",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "1 and 1=1",
    ),
    rule(
        ThreatCategory::SqlInjection,
        PatternScope::TextAndPath,
        "1' and '1'='1",
    ),
    // --- Cross-site scripting ---
    rule(ThreatCategory::Xss, PatternScope::TextAndPath, "<script"),
    rule(
        ThreatCategory::Xss,
        PatternScope::TextAndPath,
        "javascript:",
    ),
    rule(ThreatCategory::Xss, PatternScope::TextAndPath, "onerror="),
    rule(ThreatCategory::Xss, PatternScope::TextAndPath, "onload="),
    rule(ThreatCategory::Xss, PatternScope::TextAndPath, "onclick="),
    rule(
        ThreatCategory::Xss,
        PatternScope::TextAndPath,
        "onmouseover=",
    ),
    rule(ThreatCategory::Xss, PatternScope::TextAndPath, "<img src="),
    rule(ThreatCategory::Xss, PatternScope::TextAndPath, "<svg "),
    rule(ThreatCategory::Xss, PatternScope::TextAndPath, "<iframe"),
    rule(ThreatCategory::Xss, PatternScope::TextAndPath, "alert("),
    rule(
        ThreatCategory::Xss,
        PatternScope::TextAndPath,
        "document.cookie",
    ),
    rule(ThreatCategory::Xss, PatternScope::TextAndPath, "eval("),
    // --- Path traversal (path only) ---
    rule(ThreatCategory::PathTraversal, PatternScope::Path, "../"),
    rule(ThreatCategory::PathTraversal, PatternScope::Path, "..\\"),
    rule(ThreatCategory::PathTraversal, PatternScope::Path, "..%2f"),
    rule(ThreatCategory::PathTraversal, PatternScope::Path, "..%5c"),
    rule(ThreatCategory::PathTraversal, PatternScope::Path, "%2e%2e/"),
    rule(ThreatCategory::PathTraversal, PatternScope::Path, "....//"),
    rule(
        ThreatCategory::PathTraversal,
        PatternScope::Path,
        "/etc/passwd",
    ),
    rule(
        ThreatCategory::PathTraversal,
        PatternScope::Path,
        "/etc/shadow",
    ),
    rule(
        ThreatCategory::PathTraversal,
        PatternScope::Path,
        "/proc/self",
    ),
    rule(
        ThreatCategory::PathTraversal,
        PatternScope::Path,
        "php://filter",
    ),
    rule(
        ThreatCategory::PathTraversal,
        PatternScope::Path,
        "php://input",
    ),
    rule(ThreatCategory::PathTraversal, PatternScope::Path, "file://"),
    // --- Brute force / credential abuse (text) ---
    rule(
        ThreatCategory::BruteForce,
        PatternScope::Text,
        "failed password",
    ),
    rule(
        ThreatCategory::BruteForce,
        PatternScope::Text,
        "authentication failure",
    ),
    rule(
        ThreatCategory::BruteForce,
        PatternScope::Text,
        "invalid user",
    ),
    rule(
        ThreatCategory::BruteForce,
        PatternScope::Text,
        "maximum authentication attempts",
    ),
    rule(
        ThreatCategory::BruteForce,
        PatternScope::Text,
        "too many authentication failures",
    ),
    rule(
        ThreatCategory::BruteForce,
        PatternScope::Text,
        "access denied",
    ),
    rule(
        ThreatCategory::BruteForce,
        PatternScope::Text,
        "login failed",
    ),
    // --- Known attack tooling in the user agent ---
    rule(ThreatCategory::Scanner, PatternScope::UserAgent, "sqlmap"),
    rule(ThreatCategory::Scanner, PatternScope::UserAgent, "nikto"),
    rule(ThreatCategory::Scanner, PatternScope::UserAgent, "nmap"),
    rule(ThreatCategory::Scanner, PatternScope::UserAgent, "masscan"),
    rule(ThreatCategory::Scanner, PatternScope::UserAgent, "hydra"),
    rule(ThreatCategory::Scanner, PatternScope::UserAgent, "medusa"),
    rule(
        ThreatCategory::Scanner,
        PatternScope::UserAgent,
        "burp suite",
    ),
    rule(
        ThreatCategory::Scanner,
        PatternScope::UserAgent,
        "dirbuster",
    ),
    rule(ThreatCategory::Scanner, PatternScope::UserAgent, "gobuster"),
    rule(ThreatCategory::Scanner, PatternScope::UserAgent, "wpscan"),
    rule(ThreatCategory::Scanner, PatternScope::UserAgent, "nuclei"),
    rule(ThreatCategory::Scanner, PatternScope::UserAgent, "ffuf"),
    rule(
        ThreatCategory::Scanner,
        PatternScope::UserAgent,
        "feroxbuster",
    ),
    rule(ThreatCategory::Scanner, PatternScope::UserAgent, "w3af"),
    // --- Probing of sensitive files (exact or directory prefix) ---
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/.env",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/.git",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/.htaccess",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/.htpasswd",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/wp-config.php",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/config/database.yml",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/config/database.yaml",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/config/secrets.yml",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/.aws/credentials",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/.ssh/id_rsa",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/proc/self/environ",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/boot.ini",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/web.config",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/phpinfo.php",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/server-status",
    ),
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/.svn",
    ),
    // Lowercase on purpose: inputs are lowercased before matching (the
    // old uppercase form never matched).
    rule(
        ThreatCategory::SensitiveFile,
        PatternScope::PathPrefix,
        "/.ds_store",
    ),
    // --- TLS failures (often client misconfiguration or scanning) ---
    rule(
        ThreatCategory::TlsError,
        PatternScope::Text,
        "ssl_do_handshake",
    ),
    rule(ThreatCategory::TlsError, PatternScope::Text, "ssl_error"),
    rule(
        ThreatCategory::TlsError,
        PatternScope::Text,
        "certificate verify failed",
    ),
    rule(ThreatCategory::TlsError, PatternScope::Text, "tls alert"),
    rule(
        ThreatCategory::TlsError,
        PatternScope::Text,
        "handshake failure",
    ),
];

impl PatternRule {
    /// Whether this rule's pattern occurs in the given (already
    /// lowercased) fields.
    #[must_use]
    pub fn matches(&self, text: &str, path: &str, user_agent: Option<&str>) -> bool {
        match self.scope {
            PatternScope::Text => text.contains(self.pattern),
            PatternScope::Path => path.contains(self.pattern),
            PatternScope::TextAndPath => text.contains(self.pattern) || path.contains(self.pattern),
            PatternScope::UserAgent => user_agent.is_some_and(|ua| ua.contains(self.pattern)),
            PatternScope::PathPrefix => path == self.pattern || path.starts_with(self.pattern),
        }
    }
}
