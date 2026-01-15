use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_history_prune_older_than() {
    // Create a temp dir for the database
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("history.db");

    // Populate the database with some old and new entries
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        // Create the full schema to avoid migration errors
        conn.execute(
            r"CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                agent_type TEXT NOT NULL,
                working_dir TEXT NOT NULL,
                command TEXT NOT NULL,
                command_hash TEXT NOT NULL,
                outcome TEXT NOT NULL,
                pack_id TEXT,
                pattern_name TEXT,
                eval_duration_us INTEGER DEFAULT 0,
                session_id TEXT,
                exit_code INTEGER,
                parent_command_id INTEGER,
                hostname TEXT,
                allowlist_layer TEXT,
                bypass_code TEXT
            )",
            [],
        )
        .unwrap();

        // Also create schema_version to skip initialization logic
        conn.execute(
            r"CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now')),
                description TEXT NOT NULL DEFAULT 'Initial schema'
            )",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO schema_version (version, description) VALUES (2, 'Test setup')",
            [],
        )
        .unwrap();

        // Insert old entry (30 days ago)
        conn.execute(
            "INSERT INTO commands (timestamp, agent_type, working_dir, command, command_hash, outcome)
             VALUES (
                strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-30 days')),
                'claude_code', '/tmp', 'git status', 'hash1', 'allow'
             )",
            [],
        ).unwrap();

        // Insert recent entry (1 day ago)
        conn.execute(
            "INSERT INTO commands (timestamp, agent_type, working_dir, command, command_hash, outcome)
             VALUES (
                strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-1 day')),
                'claude_code', '/tmp', 'git status', 'hash2', 'allow'
             )",
            [],
        ).unwrap();
    }

    // Run prune command
    let mut cmd = Command::cargo_bin("dcg").unwrap();
    cmd.env("DCG_HISTORY_DB", &db_path)
        .env("DCG_HISTORY_ENABLED", "true")
        .args(&["history", "prune", "--older-than-days", "7", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Pruned 1 entries"));

    // Verify database content
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1, "Should have 1 entry remaining");
    }
}

#[test]
fn test_history_prune_dry_run() {
    // Create a temp dir for the database
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("history.db");

    // Populate with old data
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        // Create the full schema to avoid migration errors
        conn.execute(
            r"CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                agent_type TEXT NOT NULL,
                working_dir TEXT NOT NULL,
                command TEXT NOT NULL,
                command_hash TEXT NOT NULL,
                outcome TEXT NOT NULL,
                pack_id TEXT,
                pattern_name TEXT,
                eval_duration_us INTEGER DEFAULT 0,
                session_id TEXT,
                exit_code INTEGER,
                parent_command_id INTEGER,
                hostname TEXT,
                allowlist_layer TEXT,
                bypass_code TEXT
            )",
            [],
        )
        .unwrap();

        // Also create schema_version to skip initialization logic
        conn.execute(
            r"CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now')),
                description TEXT NOT NULL DEFAULT 'Initial schema'
            )",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO schema_version (version, description) VALUES (2, 'Test setup')",
            [],
        )
        .unwrap();

        // Insert old entry (30 days ago)
        conn.execute(
            "INSERT INTO commands (timestamp, agent_type, working_dir, command, command_hash, outcome)
             VALUES (
                strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-30 days')),
                'claude_code', '/tmp', 'git status', 'hash1', 'allow'
             )",
            [],
        ).unwrap();
    }

    // Run prune command with dry-run
    let mut cmd = Command::cargo_bin("dcg").unwrap();
    cmd.env("DCG_HISTORY_DB", &db_path)
        .env("DCG_HISTORY_ENABLED", "true")
        .args(&["history", "prune", "--older-than-days", "7", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Would prune 1 entries"));

    // Verify database content (nothing should be deleted)
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1, "Should still have 1 entry");
    }
}
