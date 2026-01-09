//! Command normalization for wrapper prefix stripping.
//!
//! This module strips common wrapper prefixes (sudo, env, backslash escapes, command)
//! so destructive patterns match consistently regardless of how commands are invoked.
//!
//! # Design Principles
//!
//! - **Conservative**: Only strip wrappers when syntax is unambiguous.
//! - **Non-destructive**: Never change the meaning of non-wrapper commands.
//! - **Preserve original**: Return both original and normalized forms for explain output.
//!
//! # Supported Wrappers
//!
//! - `sudo [-EHnkKSb] [-u user] [-g group] ...` - privilege escalation
//! - `env [-i] [-u name] [NAME=VALUE]... command` - environment modification
//! - `\git`, `\rm` - bash alias bypass (leading backslash)
//! - `command [-p] [--] cmd` - but NOT `command -v` or `command -V` (query mode)

use std::borrow::Cow;

/// Result of command normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedCommand<'a> {
    /// The original command, unchanged.
    pub original: &'a str,
    /// The normalized command with wrappers stripped.
    /// Same as original if no wrappers were stripped.
    pub normalized: Cow<'a, str>,
    /// List of wrappers that were stripped (for explain/debug output).
    pub stripped_wrappers: Vec<StrippedWrapper>,
}

/// A wrapper that was stripped from the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrippedWrapper {
    /// The wrapper type (e.g., "sudo", "env", "backslash", "command").
    pub wrapper_type: &'static str,
    /// The exact text that was stripped.
    pub stripped_text: String,
}

impl<'a> NormalizedCommand<'a> {
    /// Create a new normalized command where no wrappers were stripped.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec::new() is not const-stable
    pub fn unchanged(command: &'a str) -> Self {
        Self {
            original: command,
            normalized: Cow::Borrowed(command),
            stripped_wrappers: Vec::new(),
        }
    }

    /// Check if any normalization was performed.
    #[must_use]
    pub fn was_normalized(&self) -> bool {
        !self.stripped_wrappers.is_empty()
    }
}

/// Normalize a command by stripping common wrapper prefixes.
///
/// Returns the original command alongside the normalized form and a list of
/// stripped wrappers for debugging/explain purposes.
///
/// # Examples
///
/// ```ignore
/// let result = strip_wrapper_prefixes("sudo git reset --hard");
/// assert_eq!(result.normalized, "git reset --hard");
/// assert_eq!(result.stripped_wrappers[0].wrapper_type, "sudo");
/// ```
#[must_use]
pub fn strip_wrapper_prefixes(command: &str) -> NormalizedCommand<'_> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return NormalizedCommand::unchanged(command);
    }

    let mut current = trimmed.to_string();
    let mut stripped_wrappers = Vec::new();

    // Iteratively strip wrappers until no more are found
    loop {
        let before_len = current.len();

        // Try stripping each wrapper type in order
        if let Some((remaining, wrapper)) = strip_sudo(&current) {
            stripped_wrappers.push(wrapper);
            current = remaining;
            continue;
        }

        if let Some((remaining, wrapper)) = strip_env(&current) {
            stripped_wrappers.push(wrapper);
            current = remaining;
            continue;
        }

        if let Some((remaining, wrapper)) = strip_command_wrapper(&current) {
            stripped_wrappers.push(wrapper);
            current = remaining;
            continue;
        }

        if let Some((remaining, wrapper)) = strip_leading_backslash(&current) {
            stripped_wrappers.push(wrapper);
            current = remaining;
            continue;
        }

        // No more wrappers found
        if current.len() == before_len {
            break;
        }
    }

    if stripped_wrappers.is_empty() {
        NormalizedCommand::unchanged(command)
    } else {
        NormalizedCommand {
            original: command,
            normalized: Cow::Owned(current),
            stripped_wrappers,
        }
    }
}

/// Strip `sudo` prefix with its options.
///
/// Handles: `-E`, `-H`, `-n`, `-k`, `-K`, `-S`, `-b`, `-u <user>`, `-g <group>`,
/// `-h <host>`, `-p <prompt>`, and `--` terminator.
fn strip_sudo(command: &str) -> Option<(String, StrippedWrapper)> {
    // Options that take no argument
    const SIMPLE_FLAGS: &[char] = &['E', 'H', 'n', 'k', 'K', 'S', 'b', 'i', 'P', 'A'];
    // Options that take an argument
    const ARG_FLAGS: &[char] = &['u', 'g', 'h', 'p', 'C', 'r', 'U'];

    let trimmed = command.trim_start();
    if !trimmed.starts_with("sudo") {
        return None;
    }

    // Must be followed by whitespace or end
    let after_sudo = &trimmed[4..];
    if !after_sudo.is_empty() && !after_sudo.starts_with(char::is_whitespace) {
        return None;
    }

    let rest = after_sudo.trim_start();
    let mut idx = 0;
    let bytes = rest.as_bytes();

    while idx < bytes.len() {
        // Skip whitespace
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() {
            break;
        }

        // Check for -- terminator
        if bytes[idx] == b'-' && idx + 1 < bytes.len() && bytes[idx + 1] == b'-' {
            // Check if it's exactly "--" followed by whitespace or end
            if idx + 2 >= bytes.len() || bytes[idx + 2].is_ascii_whitespace() {
                idx += 2;
                while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                    idx += 1;
                }
                break;
            }
        }

        if bytes[idx] != b'-' {
            break;
        }

        // Parse one option token (e.g., -E, -EH, -uuser)
        let token_start = idx;
        let mut token_end = idx + 1;
        while token_end < bytes.len() && !bytes[token_end].is_ascii_whitespace() {
            token_end += 1;
        }

        if token_end <= token_start + 1 {
            break;
        }

        let token = &rest[token_start..token_end];
        if token == "--" {
            idx = token_end;
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            break;
        }

        if token.starts_with("--") {
            // Unknown long option - stop parsing sudo options
            break;
        }

        let mut needs_arg = false;
        let mut unknown_flag = false;
        let mut saw_arg_inline = false;
        let mut chars = token[1..].chars().peekable();

        while let Some(flag) = chars.next() {
            if SIMPLE_FLAGS.contains(&flag) {
                continue;
            }
            if ARG_FLAGS.contains(&flag) {
                if chars.peek().is_some() {
                    // Inline argument (e.g., -uroot)
                    saw_arg_inline = true;
                } else {
                    needs_arg = true;
                }
                // Arg flags consume the rest of the token (if any)
                break;
            }
            unknown_flag = true;
            break;
        }

        if unknown_flag {
            break;
        }

        idx = token_end;

        if saw_arg_inline {
            continue;
        }

        if needs_arg {
            // Skip whitespace before argument
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            if idx >= bytes.len() {
                // Missing argument - don't strip
                return None;
            }
            // Skip argument token
            while idx < bytes.len() && !bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
        }
    }

    // Skip any remaining whitespace
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }

    let remaining = &rest[idx..];
    if remaining.is_empty() {
        // sudo with no command - don't strip
        return None;
    }

    let stripped_text = trimmed[..trimmed.len() - remaining.len()]
        .trim_end()
        .to_string();

    Some((
        remaining.to_string(),
        StrippedWrapper {
            wrapper_type: "sudo",
            stripped_text,
        },
    ))
}

/// Strip `env` prefix with options and environment variable assignments.
///
/// Handles: `-i`, `-u <name>`, `--ignore-environment`, and `NAME=VALUE` assignments.
fn strip_env(command: &str) -> Option<(String, StrippedWrapper)> {
    let trimmed = command.trim_start();
    if !trimmed.starts_with("env") {
        return None;
    }

    // Must be followed by whitespace or end
    let after_env = &trimmed[3..];
    if !after_env.is_empty() && !after_env.starts_with(char::is_whitespace) {
        return None;
    }

    let rest = after_env.trim_start();
    if rest.is_empty() {
        // Just "env" with no args - don't strip (it prints environment)
        return None;
    }

    let mut idx = 0;
    let bytes = rest.as_bytes();

    while idx < bytes.len() {
        // Skip whitespace
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() {
            break;
        }

        // Check for options
        if bytes[idx] == b'-' {
            // Check for --ignore-environment
            if rest[idx..].starts_with("--ignore-environment") {
                idx += 20;
                continue;
            }
            if rest[idx..].starts_with("--") {
                // -- terminates options
                idx += 2;
                while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                    idx += 1;
                }
                break;
            }

            idx += 1;
            if idx >= bytes.len() {
                break;
            }

            let flag = bytes[idx] as char;
            match flag {
                'i' | '0' => {
                    idx += 1;
                    continue;
                }
                'u' | 'S' | 'P' | 'C' => {
                    // Takes an argument
                    idx += 1;
                    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                        idx += 1;
                    }
                    while idx < bytes.len() && !bytes[idx].is_ascii_whitespace() {
                        idx += 1;
                    }
                    continue;
                }
                _ => {
                    // Unknown option - stop
                    break;
                }
            }
        }

        // Check for NAME=VALUE assignment
        let start = idx;
        let mut has_equals = false;

        // Check if this looks like an assignment (NAME=VALUE)
        while idx < bytes.len() && !bytes[idx].is_ascii_whitespace() {
            if bytes[idx] == b'=' {
                has_equals = true;
            }
            idx += 1;
        }

        if has_equals && start < idx {
            // It's an assignment, skip it
            continue;
        }
        // Not an assignment - this is the command
        idx = start;
        break;
    }

    // Skip any remaining whitespace
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }

    let remaining = &rest[idx..];
    if remaining.is_empty() {
        // env with no command (just assignments) - don't strip
        return None;
    }

    let stripped_text = trimmed[..trimmed.len() - remaining.len()]
        .trim_end()
        .to_string();

    Some((
        remaining.to_string(),
        StrippedWrapper {
            wrapper_type: "env",
            stripped_text,
        },
    ))
}

/// Strip `command` wrapper, but NOT when used in query mode (`-v`/`-V`).
fn strip_command_wrapper(command: &str) -> Option<(String, StrippedWrapper)> {
    let trimmed = command.trim_start();
    if !trimmed.starts_with("command") {
        return None;
    }

    // Must be followed by whitespace
    let after_command = &trimmed[7..];
    if !after_command.starts_with(char::is_whitespace) {
        return None;
    }

    let rest = after_command.trim_start();
    if rest.is_empty() {
        return None;
    }

    let mut idx = 0;
    let bytes = rest.as_bytes();

    while idx < bytes.len() {
        // Skip whitespace
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() {
            break;
        }

        if bytes[idx] != b'-' {
            break;
        }

        // Parse one option token (e.g., -p, -pv, --)
        let token_start = idx;
        let mut token_end = idx + 1;
        while token_end < bytes.len() && !bytes[token_end].is_ascii_whitespace() {
            token_end += 1;
        }

        if token_end <= token_start + 1 {
            break;
        }

        let token = &rest[token_start..token_end];
        if token == "--" {
            idx = token_end;
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            break;
        }
        if token.starts_with("--") {
            // Unknown long option - stop
            break;
        }

        let mut unknown = false;
        for flag in token[1..].chars() {
            match flag {
                'v' | 'V' => {
                    // Query mode - NOT a wrapper
                    return None;
                }
                'p' => {}
                _ => {
                    unknown = true;
                    break;
                }
            }
        }
        if unknown {
            break;
        }

        idx = token_end;
    }

    // Skip any remaining whitespace
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }

    let remaining = &rest[idx..];
    if remaining.is_empty() {
        return None;
    }

    let stripped_text = trimmed[..trimmed.len() - remaining.len()]
        .trim_end()
        .to_string();

    Some((
        remaining.to_string(),
        StrippedWrapper {
            wrapper_type: "command",
            stripped_text,
        },
    ))
}

/// Strip leading backslash from the first command token.
///
/// This handles bash alias bypass: `\git` instead of `git`.
fn strip_leading_backslash(command: &str) -> Option<(String, StrippedWrapper)> {
    let trimmed = command.trim_start();
    if !trimmed.starts_with('\\') {
        return None;
    }

    // Get the first token (command name)
    let rest = &trimmed[1..];
    if rest.is_empty() {
        return None;
    }

    // Find end of first token
    let first_token_end = rest.find(char::is_whitespace).unwrap_or(rest.len());

    let first_token = &rest[..first_token_end];

    // Only strip if the token looks like a valid command name (alphanumeric + underscore/dash)
    if first_token.is_empty()
        || !first_token
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }

    Some((
        rest.to_string(),
        StrippedWrapper {
            wrapper_type: "backslash",
            stripped_text: "\\".to_string(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sudo_simple() {
        let result = strip_wrapper_prefixes("sudo git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
        assert_eq!(result.stripped_wrappers.len(), 1);
        assert_eq!(result.stripped_wrappers[0].wrapper_type, "sudo");
    }

    #[test]
    fn test_sudo_with_options() {
        let result = strip_wrapper_prefixes("sudo -E -H git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_with_combined_options() {
        let result = strip_wrapper_prefixes("sudo -EH git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_with_user() {
        let result = strip_wrapper_prefixes("sudo -u root git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_not_sudo_prefix() {
        let result = strip_wrapper_prefixes("sudoku play");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_env_simple() {
        let result = strip_wrapper_prefixes("env git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_env_with_assignment() {
        let result = strip_wrapper_prefixes("env GIT_DIR=.git git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_env_alone() {
        let result = strip_wrapper_prefixes("env");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_command_wrapper() {
        let result = strip_wrapper_prefixes("command git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_command_v_not_wrapper() {
        let result = strip_wrapper_prefixes("command -v git");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_command_pv_not_wrapper() {
        let result = strip_wrapper_prefixes("command -pv git");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_command_p_wrapper() {
        let result = strip_wrapper_prefixes("command -p git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_backslash_git() {
        let result = strip_wrapper_prefixes("\\git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_env_chain() {
        let result = strip_wrapper_prefixes("sudo env GIT_DIR=.git git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
        assert_eq!(result.stripped_wrappers.len(), 2);
    }

    #[test]
    fn test_empty_command() {
        let result = strip_wrapper_prefixes("");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_no_wrappers() {
        let result = strip_wrapper_prefixes("git status");
        assert!(!result.was_normalized());
    }
}
