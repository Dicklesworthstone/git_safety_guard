//! Command history database for DCG.
//!
//! This module provides SQLite-based history collection and querying for
//! tracking all commands evaluated by DCG across agent sessions.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      HistoryDb                                 │
//! │  (SQLite database for command history and analytics)            │
//! └─────────────────────────────────────────────────────────────────┘
//!                                  │
//!           ┌──────────────────────┼──────────────────────┐
//!           ▼                      ▼                      ▼
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │  commands table │    │  commands_fts   │    │ schema_version  │
//! │  (main storage) │    │  (full-text)    │    │  (migrations)   │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use destructive_command_guard::history::{HistoryDb, CommandEntry, Outcome};
//!
//! let db = HistoryDb::open(None)?; // Uses default path
//! db.log_command(&CommandEntry {
//!     timestamp: chrono::Utc::now(),
//!     agent_type: "claude_code".into(),
//!     working_dir: "/path/to/project".into(),
//!     command: "git status".into(),
//!     outcome: Outcome::Allow,
//!     ..Default::default()
//! })?;
//! ```

mod schema;

use crate::config::{HistoryConfig, HistoryRedactionMode};
use crate::logging::{RedactionConfig, RedactionMode};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tracing::warn;

pub use schema::{
    CURRENT_SCHEMA_VERSION, CommandEntry, DEFAULT_DB_FILENAME, HistoryDb, HistoryError, Outcome,
};

/// Environment variable to override the history database path.
pub const ENV_HISTORY_DB_PATH: &str = "DCG_HISTORY_DB";

/// Environment variable to disable history collection entirely.
pub const ENV_HISTORY_DISABLED: &str = "DCG_HISTORY_DISABLED";

enum HistoryMessage {
    Entry(Box<CommandEntry>),
    Flush(mpsc::Sender<()>),
    Shutdown,
}

#[derive(Clone)]
pub struct HistoryFlushHandle {
    sender: mpsc::Sender<HistoryMessage>,
}

impl HistoryFlushHandle {
    /// Flush and wait for pending writes to complete.
    pub fn flush_sync(&self) {
        const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);
        let (ack_tx, ack_rx) = mpsc::channel();
        if self.sender.send(HistoryMessage::Flush(ack_tx)).is_ok() {
            let _ = ack_rx.recv_timeout(FLUSH_TIMEOUT);
        }
    }
}

/// Asynchronous history writer.
pub struct HistoryWriter {
    sender: Option<mpsc::Sender<HistoryMessage>>,
    handle: Option<thread::JoinHandle<()>>,
    redaction_mode: HistoryRedactionMode,
}

impl HistoryWriter {
    /// Create a new history writer.
    ///
    /// The writer is disabled when `config.enabled` is false.
    #[must_use]
    pub fn new(db: HistoryDb, config: &HistoryConfig) -> Self {
        if !config.enabled {
            return Self::disabled();
        }

        let (sender, receiver) = mpsc::channel::<HistoryMessage>();
        let Ok(handle) = thread::Builder::new()
            .name("dcg-history-writer".to_string())
            .spawn(move || history_worker(db, receiver))
        else {
            // Thread spawn failed - return disabled writer to avoid leaking
            // messages into a channel with no receiver.
            return Self::disabled();
        };

        Self {
            sender: Some(sender),
            handle: Some(handle),
            redaction_mode: config.redaction_mode,
        }
    }

    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            sender: None,
            handle: None,
            redaction_mode: HistoryRedactionMode::Pattern,
        }
    }

    #[must_use]
    pub fn flush_handle(&self) -> Option<HistoryFlushHandle> {
        self.sender.as_ref().map(|sender| HistoryFlushHandle {
            sender: sender.clone(),
        })
    }

    /// Log a command entry asynchronously.
    pub fn log(&self, mut entry: CommandEntry) {
        entry.command = redact_for_history(&entry.command, self.redaction_mode);
        if let Some(sender) = &self.sender {
            if let Err(e) = sender.send(HistoryMessage::Entry(Box::new(entry))) {
                warn!("Failed to queue history entry: {e}");
            }
        }
    }

    /// Request a flush without waiting for completion.
    pub fn flush(&self) {
        if let Some(sender) = &self.sender {
            let (ack_tx, _ack_rx) = mpsc::channel();
            if let Err(e) = sender.send(HistoryMessage::Flush(ack_tx)) {
                warn!("Failed to send history flush request: {e}");
            }
        }
    }

    /// Flush and wait for pending writes to complete.
    pub fn flush_sync(&self) {
        if let Some(handle) = self.flush_handle() {
            handle.flush_sync();
        }
    }
}

impl Drop for HistoryWriter {
    fn drop(&mut self) {
        self.flush_sync();

        if let Some(sender) = self.sender.take() {
            let _ = sender.send(HistoryMessage::Shutdown);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn history_worker(db: HistoryDb, receiver: mpsc::Receiver<HistoryMessage>) {
    while let Ok(message) = receiver.recv() {
        match message {
            HistoryMessage::Entry(entry) => {
                if let Err(e) = db.log_command(&entry) {
                    warn!("Failed to log command to history database: {e}");
                }
            }
            HistoryMessage::Flush(ack) => {
                let should_shutdown = drain_history_messages(&db, &receiver);
                // Ack send failure is not critical - the caller will timeout
                let _ = ack.send(());
                if should_shutdown {
                    break;
                }
            }
            HistoryMessage::Shutdown => {
                break;
            }
        }
    }
}

fn drain_history_messages(db: &HistoryDb, receiver: &mpsc::Receiver<HistoryMessage>) -> bool {
    let mut shutdown = false;
    for message in receiver.try_iter() {
        match message {
            HistoryMessage::Entry(entry) => {
                if let Err(e) = db.log_command(&entry) {
                    warn!("Failed to log command to history database: {e}");
                }
            }
            HistoryMessage::Flush(ack) => {
                let _ = ack.send(());
            }
            HistoryMessage::Shutdown => {
                shutdown = true;
            }
        }
    }
    shutdown
}

/// Secret patterns for redaction, with pattern and replacement label.
const SECRET_PATTERNS: &[(&str, &str)] = &[
    // API Keys
    (r"sk-ant-api[a-zA-Z0-9\-_]{20,}", "[ANTHROPIC_KEY]"),
    // OpenAI keys: sk-proj-..., sk-..., sk-svcacct-... etc.
    (r"sk-[a-zA-Z0-9\-]{40,}", "[OPENAI_KEY]"),
    (r"AIza[a-zA-Z0-9_\-]{35}", "[GOOGLE_API_KEY]"),
    // Cloud Provider Secrets
    (r"AKIA[A-Z0-9]{16}", "[AWS_ACCESS_KEY]"),
    (
        r#"(?i)aws_secret_access_key\s*=\s*(?:"[^"]*"|'[^']*'|\S+)"#,
        "[AWS_SECRET]",
    ),
    (
        r#"(?i)azure[_\-]?(?:storage|account)[_\-]?key\s*=\s*(?:"[^"]*"|'[^']*'|\S+)"#,
        "[AZURE_KEY]",
    ),
    // Tokens
    (r"ghp_[a-zA-Z0-9]{36}", "[GITHUB_PAT]"),
    (r"gho_[a-zA-Z0-9]{36}", "[GITHUB_OAUTH]"),
    (r"glpat-[a-zA-Z0-9\-_]{20}", "[GITLAB_PAT]"),
    (r"npm_[a-zA-Z0-9]{36}", "[NPM_TOKEN]"),
    (r"pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9\-_]+", "[PYPI_TOKEN]"),
    (r"xox[baprs]-[a-zA-Z0-9\-]+", "[SLACK_TOKEN]"),
    // Database URIs (must match user:pass@ format)
    (r"(?i)postgres://[^:]+:[^@]+@", "[POSTGRES_URI]"),
    (r"(?i)mysql://[^:]+:[^@]+@", "[MYSQL_URI]"),
    (r"(?i)mongodb(?:\+srv)?://[^:]+:[^@]+@", "[MONGO_URI]"),
    (r"(?i)redis://[^:]+:[^@]+@", "[REDIS_URI]"), // user:password format
    (r"(?i)redis://:[^@]+@", "[REDIS_URI]"),      // password-only format
    // Private Keys
    (
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "[PRIVATE_KEY]",
    ),
    (
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "[PGP_PRIVATE_KEY]",
    ),
    // JWT (header.payload.signature format)
    (
        r"eyJ[a-zA-Z0-9_\-]*\.eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*",
        "[JWT_TOKEN]",
    ),
    // Generic Secrets - be conservative to avoid false positives
    // Use [^\s\[\]] to exclude already-redacted values containing brackets
    (
        r#"(?i)(?:password|passwd|pwd)\s*[=:]\s*(?:"[^"]*"|'[^']*'|[^\s\[\]]{8,})"#,
        "[PASSWORD]",
    ),
    (
        r#"(?i)(?:secret|api[_\-]?key)\s*[=:]\s*(?:"[^"]*"|'[^']*'|[^\s\[\]]{16,})"#,
        "[SECRET]",
    ),
];

/// Compiled secret patterns for efficient reuse.
static SECRET_REGEXES: std::sync::LazyLock<Vec<(fancy_regex::Regex, &'static str)>> =
    std::sync::LazyLock::new(|| {
        SECRET_PATTERNS
            .iter()
            .filter_map(|(pattern, label)| {
                fancy_regex::Regex::new(pattern).ok().map(|re| (re, *label))
            })
            .collect()
    });

/// Redact secrets from a command string using pattern matching.
fn redact_secrets(command: &str) -> String {
    let mut result = command.to_string();
    for (regex, label) in SECRET_REGEXES.iter() {
        result = regex.replace_all(&result, *label).into_owned();
    }
    result
}

fn redact_for_history(command: &str, mode: HistoryRedactionMode) -> String {
    match mode {
        HistoryRedactionMode::None => command.to_string(),
        HistoryRedactionMode::Full => "[REDACTED]".to_string(),
        HistoryRedactionMode::Pattern => {
            // First redact secrets, then apply argument truncation
            let secrets_redacted = redact_secrets(command);
            let config = RedactionConfig {
                enabled: true,
                mode: RedactionMode::Arguments,
                ..Default::default()
            };
            crate::logging::redact_command(&secrets_redacted, &config)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Secret Redaction Tests (git_safety_guard-eod3)
    // =========================================================================

    #[test]
    fn test_anthropic_key_redaction() {
        let input =
            "curl -H 'x-api-key: sk-ant-api03-abcdefghij1234567890-xyz' https://api.anthropic.com";
        let redacted = redact_secrets(input);
        assert!(
            !redacted.contains("sk-ant-api"),
            "Anthropic key leaked: {redacted}"
        );
        assert!(
            redacted.contains("[ANTHROPIC_KEY]"),
            "Missing label: {redacted}"
        );
    }

    #[test]
    fn test_openai_key_redaction() {
        let input = "export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678";
        let redacted = redact_secrets(input);
        assert!(
            !redacted.contains("sk-proj"),
            "OpenAI key leaked: {redacted}"
        );
        assert!(
            redacted.contains("[OPENAI_KEY]"),
            "Missing label: {redacted}"
        );
    }

    #[test]
    fn test_aws_access_key_redaction() {
        let input = "aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE";
        let redacted = redact_secrets(input);
        assert!(
            !redacted.contains("AKIAIOSFODNN"),
            "AWS key leaked: {redacted}"
        );
        assert!(
            redacted.contains("[AWS_ACCESS_KEY]"),
            "Missing label: {redacted}"
        );
    }

    #[test]
    fn test_database_uri_redaction() {
        let cases = vec![
            (
                "postgres://user:password123@localhost:5432/db",
                "password123",
            ),
            ("mysql://root:secret@db.example.com/mydb", "secret"),
            (
                "mongodb+srv://admin:p4ssw0rd@cluster.mongodb.net/test",
                "p4ssw0rd",
            ),
            // Redis with user:password format
            (
                "redis://default:myredispass@redis.example.com:6379",
                "myredispass",
            ),
            // Redis with password-only format
            ("redis://:secretpass@localhost:6379", "secretpass"),
        ];

        for (uri, secret) in cases {
            let redacted = redact_secrets(uri);
            assert!(
                !redacted.contains(secret),
                "Secret leaked in {uri}: {redacted}"
            );
        }
    }

    #[test]
    fn test_github_pat_redaction() {
        let input =
            "git clone https://ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx@github.com/org/repo";
        let redacted = redact_secrets(input);
        assert!(!redacted.contains("ghp_"), "GitHub PAT leaked: {redacted}");
        assert!(
            redacted.contains("[GITHUB_PAT]"),
            "Missing label: {redacted}"
        );
    }

    #[test]
    fn test_jwt_redaction() {
        let input = "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'";
        let redacted = redact_secrets(input);
        assert!(!redacted.contains("eyJ"), "JWT leaked: {redacted}");
        assert!(
            redacted.contains("[JWT_TOKEN]"),
            "Missing label: {redacted}"
        );
    }

    #[test]
    fn test_private_key_redaction() {
        let input = r#"echo "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----""#;
        let redacted = redact_secrets(input);
        assert!(
            !redacted.contains("BEGIN RSA PRIVATE"),
            "Private key leaked: {redacted}"
        );
        assert!(
            redacted.contains("[PRIVATE_KEY]"),
            "Missing label: {redacted}"
        );
    }

    #[test]
    fn test_no_false_positives() {
        // These should NOT be redacted
        let safe_strings = vec![
            "git status",
            "npm install lodash",
            "The password field is required", // word "password" but not a secret
            "export PATH=/usr/bin",
            "sk-not-a-real-key", // Too short for OpenAI
        ];

        for s in safe_strings {
            let redacted = redact_secrets(s);
            assert_eq!(s, redacted, "False positive on: {s} -> {redacted}");
        }
    }

    #[test]
    fn test_redaction_mode_none() {
        let input =
            "curl -H 'x-api-key: sk-ant-api03-secret1234567890123' https://api.anthropic.com";
        let redacted = redact_for_history(input, HistoryRedactionMode::None);
        assert_eq!(input, redacted, "None mode should not redact");
    }

    #[test]
    fn test_redaction_mode_full() {
        let input = "any command with any content";
        let redacted = redact_for_history(input, HistoryRedactionMode::Full);
        assert_eq!(redacted, "[REDACTED]");
    }

    #[test]
    fn test_redaction_mode_pattern() {
        let input =
            "curl -H 'x-api-key: sk-ant-api03-secret1234567890123' https://api.anthropic.com";
        let redacted = redact_for_history(input, HistoryRedactionMode::Pattern);
        assert!(
            !redacted.contains("sk-ant-api"),
            "Pattern mode should redact secrets: {redacted}"
        );
        assert!(
            redacted.contains("[ANTHROPIC_KEY]"),
            "Missing label: {redacted}"
        );
    }

    #[test]
    fn test_slack_token_redaction() {
        let input = "export SLACK_BOT_TOKEN=xoxb-1234567890-abcdefghij";
        let redacted = redact_secrets(input);
        assert!(
            !redacted.contains("xoxb-"),
            "Slack token leaked: {redacted}"
        );
        assert!(
            redacted.contains("[SLACK_TOKEN]"),
            "Missing label: {redacted}"
        );
    }

    #[test]
    fn test_google_api_key_redaction() {
        let input = "curl 'https://maps.googleapis.com/maps/api/geocode/json?key=AIzaSyA1234567890123456789012345678901234'";
        let redacted = redact_secrets(input);
        assert!(
            !redacted.contains("AIza"),
            "Google API key leaked: {redacted}"
        );
        assert!(
            redacted.contains("[GOOGLE_API_KEY]"),
            "Missing label: {redacted}"
        );
    }

    #[test]
    fn test_password_redaction() {
        let input = "mysql -u root -p --password=supersecretpassword123";
        let redacted = redact_secrets(input);
        assert!(
            !redacted.contains("supersecret"),
            "Password leaked: {redacted}"
        );
        assert!(redacted.contains("[PASSWORD]"), "Missing label: {redacted}");
    }

    #[test]
    fn test_multiple_secrets_redaction() {
        let input = "curl -H 'Authorization: Bearer sk-ant-api03-abcdefghij1234567890-xyz' -H 'X-Slack-Token: xoxb-12345-abcdef' https://api.example.com";
        let redacted = redact_secrets(input);
        assert!(
            !redacted.contains("sk-ant-api"),
            "Anthropic key leaked: {redacted}"
        );
        assert!(
            !redacted.contains("xoxb-"),
            "Slack token leaked: {redacted}"
        );
        assert!(
            redacted.contains("[ANTHROPIC_KEY]"),
            "Missing Anthropic label: {redacted}"
        );
        assert!(
            redacted.contains("[SLACK_TOKEN]"),
            "Missing Slack label: {redacted}"
        );
    }

    #[test]
    fn test_redaction_performance() {
        use std::time::{Duration, Instant};

        let input = "curl -H 'Authorization: Bearer sk-ant-api03-xxxxx1234567890123' https://api.example.com";

        let start = Instant::now();
        for _ in 0..10000 {
            let _ = redact_secrets(input);
        }
        let elapsed = start.elapsed();

        // Should process 10k strings in <500ms (generous limit)
        assert!(
            elapsed < Duration::from_millis(500),
            "Redaction too slow: {elapsed:?}"
        );
    }

    #[test]
    fn test_quoted_secrets_redaction() {
        // Quoted with spaces
        let input = r#"export AWS_SECRET_ACCESS_KEY="secret with spaces""#;
        let redacted = redact_secrets(input);
        assert!(
            !redacted.contains("with spaces"),
            "Secret part leaked (quoted)!"
        );
        assert!(redacted.contains("[AWS_SECRET]"), "Missing label (quoted)");

        // Single quoted
        let input = r"export AWS_SECRET_ACCESS_KEY='secret with spaces'";
        let redacted = redact_secrets(input);
        assert!(
            !redacted.contains("with spaces"),
            "Secret part leaked (single quoted)!"
        );
        assert!(
            redacted.contains("[AWS_SECRET]"),
            "Missing label (single quoted)"
        );

        // Unquoted (no spaces)
        let input = r"export AWS_SECRET_ACCESS_KEY=secret_no_spaces";
        let redacted = redact_secrets(input);
        assert!(
            !redacted.contains("secret_no_spaces"),
            "Secret part leaked (unquoted)!"
        );
        assert!(
            redacted.contains("[AWS_SECRET]"),
            "Missing label (unquoted)"
        );

        // Quoted password
        let input = r#"password="my secret password""#;
        let redacted = redact_secrets(input);
        assert!(!redacted.contains("my secret"), "Password leaked (quoted)!");
        assert!(redacted.contains("[PASSWORD]"), "Missing label (password)");
    }
}
