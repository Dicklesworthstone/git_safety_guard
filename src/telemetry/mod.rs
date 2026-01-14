//! Command telemetry database for DCG.
//!
//! This module provides SQLite-based telemetry collection and querying for
//! tracking all commands evaluated by DCG across agent sessions.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      TelemetryDb                                 │
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
//! use destructive_command_guard::telemetry::{TelemetryDb, CommandEntry, Outcome};
//!
//! let db = TelemetryDb::open(None)?; // Uses default path
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

pub use schema::{
    CURRENT_SCHEMA_VERSION, CommandEntry, DEFAULT_DB_FILENAME, Outcome, TelemetryDb, TelemetryError,
};

/// Environment variable to override the telemetry database path.
pub const ENV_TELEMETRY_DB_PATH: &str = "DCG_TELEMETRY_DB";

/// Environment variable to disable telemetry collection entirely.
pub const ENV_TELEMETRY_DISABLED: &str = "DCG_TELEMETRY_DISABLED";
