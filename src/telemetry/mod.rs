//! Command history database for DCG.
//!
//! This module provides SQLite-based history collection and querying for
//! tracking all commands evaluated by DCG across agent sessions.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      HistoryDb                                   │
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

pub use schema::{
    AgentStat, CURRENT_SCHEMA_VERSION, CommandEntry, DEFAULT_DB_FILENAME, ExportFilters,
    ExportOptions, ExportedData, HistoryDb, HistoryError, HistoryStats, Outcome, OutcomeStats,
    PackEffectivenessAnalysis, PackRecommendation, PatternEffectiveness, PatternStat,
    PerformanceStats, PotentialGap, ProjectStat, RecommendationType, StatsTrends,
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
            let _ = sender.send(HistoryMessage::Entry(Box::new(entry)));
        }
    }

    /// Request a flush without waiting for completion.
    pub fn flush(&self) {
        if let Some(sender) = &self.sender {
            let (ack_tx, _ack_rx) = mpsc::channel();
            let _ = sender.send(HistoryMessage::Flush(ack_tx));
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
                let _ = db.log_command(&entry);
            }
            HistoryMessage::Flush(ack) => {
                let should_shutdown = drain_history_messages(&db, &receiver);
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
                let _ = db.log_command(&entry);
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

fn redact_for_history(command: &str, mode: HistoryRedactionMode) -> String {
    match mode {
        HistoryRedactionMode::None => command.to_string(),
        HistoryRedactionMode::Full => "[REDACTED]".to_string(),
        HistoryRedactionMode::Pattern => {
            let config = RedactionConfig {
                enabled: true,
                mode: RedactionMode::Arguments,
                ..Default::default()
            };
            crate::logging::redact_command(command, &config)
        }
    }
}
