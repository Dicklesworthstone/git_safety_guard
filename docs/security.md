# Security Notes: Heredoc Detection

This document describes the threat model, assumptions, and incident response
for heredoc and inline-script scanning.

## Threat Model

Heredoc scanning is designed to catch destructive operations hidden inside
embedded scripts, including:

- Heredocs: `<<EOF ... EOF`
- Here-strings: `<<< "..."`
- Inline interpreter flags: `python -c`, `bash -c`, `node -e`
- Piped scripts: `cat <<EOF | bash`

The goal is to prevent accidental or automated destructive actions that the
outer command does not reveal.

## What It Protects Against

- Destructive filesystem commands inside scripts (for example, recursive delete)
- Destructive git operations embedded in scripts (for example, `git reset --hard`)
- Shell execution helpers in scripting languages (for example, `os.system`,
  `child_process.execSync`, `Kernel.system`)

## Out of Scope

- General malware detection
- Exploits that do not rely on heredocs or inline script payloads
- Non-shell destructive operations outside the supported language set
- Arbitrary interpreter behavior that is not represented in the AST patterns

These limits keep runtime overhead small and false positives manageable.

## Fail-Open Behavior

In hook mode, heredoc scanning is **fail-open** by design:

- Parse errors or timeouts result in ALLOW
- Unknown languages result in ALLOW

This prevents the hook from breaking legitimate workflows. Diagnostic markers
are emitted so that `dcg explain` or logs can surface the failure.

## Performance Budgets

The heredoc pipeline is strictly bounded:

- Tier 1 trigger: <100us
- Tier 2 extraction: <1ms typical, 50ms max
- Tier 3 AST match: <5ms typical, 20ms max

When budgets are exceeded, the system fails open and records a diagnostic.

## Bypass Considerations

Heredoc scanning is not intended to be a perfect malware detector. Known
limitations include:

- Obfuscated payloads that evade AST parsing or use unsupported languages
- Dynamic command construction that cannot be resolved to literal payloads
- Non-standard interpreters or runtime-generated code

Mitigations:

- Favor stable rule IDs and allowlisting for known-safe cases
- Keep patterns narrowly scoped to avoid broad false positives
- Expand language support and pattern coverage based on real-world feedback

## Incident Response

### If a safe command is blocked

1. Run `dcg explain` on the command or use the printed rule ID.
2. Add a scoped allowlist entry with a reason.
3. Consider reducing scope (project allowlist vs user/system allowlist).

### If a dangerous command is allowed

1. Capture the command text and environment context.
2. File a security issue with the rule ID or gap description.
3. Add or refine a heredoc pattern and tests.

## Reporting

Security issues should be reported via GitHub issues with:

- The command and any heredoc payload (redacted as needed)
- The language detected (if any)
- The observed behavior (blocked or allowed)
- Expected behavior and rationale

