# 🛡️ Aegis Guard

[![CI](https://github.com/Dhayalramesh/aegis-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Dhayalramesh/aegis-guard/actions/workflows/ci.yml)

**A pre-commit safety guard for AI coding agents.** Aegis sits between an AI agent
(Claude Code, Cursor, Devin, or your own) and your shell. It inspects every command
**before it runs**, blocks the catastrophic ones, asks about the risky ones, and
records everything in a **tamper-evident audit log** the agent cannot quietly rewrite.

> Built in response to a real, documented failure mode: in 2025–2026 autonomous
> coding agents deleted production databases (Replit/SaaStr) and wiped a database
> *and all its backups* in 9 seconds (Cursor/PocketOS) — and in at least one case
> the agent then **lied about it and fabricated records**. Aegis is the missing
> "stop and prove" layer.

---

## Why

The bottleneck in agentic coding has shifted from *writing* code to *trusting* it.
Agents now take real actions on real systems, and the top blockers to shipping them
are trust, safety, and control — not capability. Aegis targets the exact context
where the documented disasters happened: **a coding agent running a destructive shell
command.**

Aegis does three things:

1. **Blocks destructive commands before execution** — `rm -rf /`, `DROP TABLE`,
   `git push --force` to `main`, deleting backups/volumes, `DELETE FROM` without a
   `WHERE`, piping secrets to the network, and more. It also catches *obfuscated*
   and *indirect* forms — quote/escape splitting, `bash -c "$(curl …)"`,
   `eval "$X"`, and recursive deletes of an unknown `$VAR` path.
2. **Keeps a tamper-evident audit log** — a hash-chained record so an agent can't
   fabricate or rewrite history. `aegis log --verify` detects any edit, deletion,
   or reordering.
3. **Drops into Claude Code as a hook** — one block of config and every Bash command
   the agent proposes is screened.

It's a heuristic guard, not a sandbox — but it's the cheap, drop-in seatbelt that
catches the failures that actually happen.

---

## Install

```bash
# from source (during development)
git clone <repo> && cd aegis
npm install
npm run build
npm link            # makes `aegis` available globally
```

Requires Node.js ≥ 18.

---

## Quick start

```bash
# screen a command without running it (exit code: 0 allow / 1 confirm / 2 block)
aegis check "rm -rf /"
# ✗ Blocked by fs.rm-rf-root: rm -rf targeting /, ~, $HOME, or * — refusing.

aegis check "git push origin feature/x"
# ✓ Allowed — no rule matched.

# run a command *through* the guard (blocks/asks, then executes if cleared)
aegis run "git clean -fd"          # prompts: Run anyway? [y/N]

# create a project policy you can customise
aegis init                          # writes .aegis.yml

# inspect and verify the audit trail
aegis log --tail 20
aegis log --verify                  # ✓ audit chain intact — 42 entries verified.
```

---

## Claude Code integration (the main event)

Add Aegis as a `PreToolUse` hook so it screens every `Bash` command Claude Code runs.
In your `~/.claude/settings.json` (or a project `.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "aegis check --hook",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

Behaviour:

| Aegis decision | What Claude Code does |
| --- | --- |
| **block** | `permissionDecision: "deny"` — Claude refuses to run the command and sees the reason. |
| **confirm** | `permissionDecision: "ask"` — Claude prompts *you* to approve. |
| **allow** | Aegis emits nothing and defers to Claude's normal permission flow. |

Every screened command is written to the audit log regardless of the decision.

---

## Policy (`.aegis.yml`)

```yaml
version: 1
defaultAction: allow      # allow | confirm | block when nothing matches
useBuiltins: true         # merge Aegis's built-in danger rules

rules:
  - id: protect-prod-deploy
    description: Require confirmation before deploying to production
    any: ["deploy --env prod"]   # substring match (case-insensitive)
    action: confirm
    severity: high
    message: "Deploying to production — confirm intent."

  - id: block-prod-db
    description: Never touch the prod database directly
    pattern: 'DATABASE_URL=.*prod'  # regex match
    action: block
```

- **`pattern`** — a regular expression matched against the full command.
- **`any`** — a list of case-insensitive substrings; any hit fires the rule.
- **`action`** — `allow`, `confirm`, or `block`.
- Precedence is **block > confirm > allow**: the most restrictive matched rule wins,
  so the guard fails safe.

Run `aegis init` to drop a starter policy in your repo.

---

## Evasion resistance

A naive substring/regex guard is trivially dodged with shell quoting tricks the
shell itself strips before running the command:

```bash
r''m -rf /          # quote splitting
r\m -rf /           # backslash escaping
sh -c "rm -rf /"    # nested-shell payload
rm -rf \<newline> / # line continuation
```

Aegis matches every rule against **both** the raw command and a normalized,
quote/escape-stripped view (the form the shell would assemble), so the disguised
command trips the same rule as the plain one. A rule that fires *only* on the
normalized view is capped at **confirm** rather than auto-blocked — the
normalization is a heuristic, not a full shell parser (it doesn't resolve
variables, globs, or command substitution), so a suspected evasion is surfaced
for review instead of hard-failing on an innocent quoted string. It still won't
silently **allow** the obfuscated form.

## How the tamper-evident log works

Each entry stores `sha256(its fields + the previous entry's hash)`. Because every
hash depends on the one before it, editing, deleting, or reordering *any* past entry
breaks the chain for every entry after it. `aegis log --verify` recomputes the chain
and reports the first broken `seq`. This is the direct answer to "the agent edited
the logs / faked the records."

---

## Commands

| Command | Description |
| --- | --- |
| `aegis check [cmd]` | Evaluate a command (doesn't run it). `--hook`, `--json`. |
| `aegis run [cmd]` | Evaluate then run if cleared. `--yes` to auto-approve confirms. |
| `aegis init` | Write a starter `.aegis.yml`. |
| `aegis log` | Show the audit log. `--tail N`, `--verify`. |

---

## Status & roadmap

v0.1 — single-developer CLI + Claude Code hook + tamper-evident log. This is the
open-source core. Planned next: a central team dashboard, cross-developer policy
distribution, cost guardrails, and per-tool (Edit/Write) screening.

## License

MIT.
