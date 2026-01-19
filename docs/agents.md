# Agent-Specific Profiles

dcg can detect which AI coding agent is invoking it and apply agent-specific
trust levels and configuration overrides. This allows you to grant higher
trust to well-behaved agents while maintaining strict controls for unknown ones.

## Supported Agents

| Agent | Detection Method | Environment Variable |
|-------|------------------|---------------------|
| Claude Code | Environment | `CLAUDE_CODE=1` or `CLAUDE_SESSION_ID` |
| Aider | Environment | `AIDER_SESSION=1` |
| Continue | Environment | `CONTINUE_SESSION_ID` |
| Codex CLI | Environment | `CODEX_CLI=1` |
| Gemini CLI | Environment | `GEMINI_CLI=1` |

## Detection Priority

Agent detection follows this priority order:

1. **Explicit `--agent` flag**: Manual override via CLI
2. **Environment variables**: Most agents set identifying env vars
3. **Parent process inspection**: Fallback check of process tree
4. **Unknown**: Default when no agent is detected

## Trust Levels

Three trust levels control how strictly dcg evaluates commands:

| Level | Description |
|-------|-------------|
| `high` | Relaxed evaluation; agent has proven reliable |
| `medium` | Default; standard evaluation rules apply |
| `low` | Strict evaluation; extra caution for unknown agents |

## Configuration

Configure agent profiles in your `config.toml`:

```toml
# Trust Claude Code more (it sets CLAUDE_CODE=1)
[agents.claude-code]
trust_level = "high"
additional_allowlist = ["npm run build", "cargo test"]

# Restrict unknown agents
[agents.unknown]
trust_level = "low"
extra_packs = ["paranoid"]

# Default profile for unspecified agents
[agents.default]
trust_level = "medium"
```

### Profile Options

| Option | Type | Description |
|--------|------|-------------|
| `trust_level` | string | `"high"`, `"medium"`, or `"low"` |
| `disabled_packs` | array | Packs to disable for this agent |
| `extra_packs` | array | Additional packs to enable |
| `additional_allowlist` | array | Commands to allowlist for this agent |
| `disabled_allowlist` | bool | If true, ignore base allowlist for this agent |

### Example: Restrictive Config for CI

```toml
# In .dcg.toml (project-level)
[agents.unknown]
trust_level = "low"
disabled_allowlist = true
extra_packs = ["core", "database", "filesystem"]

[agents.claude-code]
trust_level = "medium"
additional_allowlist = ["npm test", "npm run lint"]
```

## Custom Agents

Define profiles for custom agents by setting an environment variable:

```bash
# Set a custom agent identifier
export MY_BUILD_BOT=1
```

Then configure in `config.toml`:

```toml
[agents.my-build-bot]
trust_level = "high"
additional_allowlist = ["make deploy"]
```

## Profile Resolution

When resolving which profile to use:

1. Look for exact match: `agents.<agent-config-key>`
2. Fall back to `agents.unknown` if agent is unrecognized
3. Fall back to `agents.default` if no specific profile exists

## Verbose Output

Use `--verbose` or `-v` to see agent detection info:

```bash
$ dcg test "git push --force" --verbose
Command: git push --force
...
Elapsed: 21.14ms
Agent: Claude Code
Trust level: medium
Severity: critical
```

Use `-vv` for detailed debug output:

```bash
$ dcg test "git push --force" -vv
...
Agent detection:
  Detected: Claude Code (claude-code)
  Method: environment_variable
  Matched: CLAUDE_CODE
  Profile: agents.claude-code
  Trust level: medium
```

## JSON Output

The `--format json` output includes agent information:

```json
{
  "command": "git push --force",
  "decision": "deny",
  "agent": {
    "detected": "claude-code",
    "trust_level": "medium",
    "detection_method": "environment_variable"
  }
}
```

## Best Practices

1. **Start with defaults**: The default `medium` trust level is safe for most
   use cases.

2. **Grant trust incrementally**: Only increase trust for agents after
   observing their behavior.

3. **Use project-level configs**: Put agent profiles in `.dcg.toml` so they're
   version-controlled with your project.

4. **Restrict unknown agents**: Always configure `agents.unknown` with lower
   trust in production environments.

5. **Review the JSON output**: Use `--format json` in CI to audit which agents
   are accessing your codebase.
