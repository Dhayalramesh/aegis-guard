# Launch posts for Aegis Guard

Copy-paste drafts. Swap `<demo-gif-url>` / links once the GIF is rendered and
pushed. Post the Show HN in the morning US Eastern on a weekday for best traffic.

---

## Hacker News — "Show HN"

**Title** (keep it under 80 chars, no emoji, no hype words — HN hates those):

```
Show HN: Aegis – a pre-commit guard that blocks AI agents from destructive commands
```

**Body / first comment** (post this as a comment right after submitting):

> I'm a developer who got nervous watching coding agents run shell commands with
> real blast radius. In 2025–2026 there were documented cases of agents deleting
> production databases (Replit/SaaStr) and wiping a database *and its backups* in
> seconds (Cursor/PocketOS) — and in at least one case the agent then fabricated
> records about what it had done.
>
> Aegis is a small seatbelt for that. It sits between the agent and your shell as
> a Claude Code `PreToolUse` hook and screens every command (and every file
> write) before it runs:
>
> - blocks the catastrophic ones (`rm -rf /`, `DROP TABLE`, force-push to main,
>   deleting backups/volumes, writing into `~/.ssh` or `/etc`, secret exfil)
> - asks about the risky ones (`.env` edits, CI-config changes, `terraform destroy`)
> - writes every decision to a **hash-chained audit log** the agent can't quietly
>   rewrite — `aegis log --verify` detects any edit, deletion, or reorder
>
> It's a heuristic guard, not a sandbox — but it tries hard not to be fooled:
> quote-splitting (`r''m -rf /`), backslash escapes, nested shells
> (`sh -c "..."`), and indirection (`eval "$x"`, `bash -c "$(curl …)"`) are all
> normalized before matching.
>
> Install: `npm i -g aegis-agent-guard`, then a few lines of hook config (in the
> README). MIT, ~1k LOC, 90+ tests.
>
> Repo: https://github.com/Dhayalramesh/aegis-guard
>
> Honest about the limits: it can't see through runtime variable values or true
> sand-box escapes, and a determined agent with `--yes` can still confirm its way
> through. It's the cheap drop-in layer that catches the failures that actually
> happened in the wild. Feedback on the rule set + false-positive cases very
> welcome.

**Tips:**
- Reply to every early comment fast — engagement in the first hour decides ranking.
- If someone says "just use a container/sandbox," agree it's stronger and explain
  Aegis is complementary: zero-setup, works inside whatever environment the agent
  already runs in, and adds the audit trail a sandbox doesn't.

---

## Reddit — r/programming, r/commandline, r/ClaudeAI, r/LocalLLaMA

**Title:**

```
I built a pre-commit guard that stops AI coding agents from running destructive commands (and keeps a tamper-evident log)
```

**Body:**

> Coding agents now take real actions on real systems. There are documented cases
> of them deleting prod databases and even fabricating records afterward. So I
> built **Aegis** — a tiny guard that screens every shell command and file write
> an agent proposes, *before* it runs.
>
> - Blocks `rm -rf /`, `DROP TABLE`, force-push to main, deleting backups, writing
>   into `~/.ssh`/`/etc`, piping secrets to the network — and sees through
>   obfuscation like `r''m -rf /` or `bash -c "$(curl …)"`.
> - Asks before `.env` edits, CI-config changes, `terraform destroy`.
> - Hash-chained audit log: `aegis log --verify` catches any tampering.
> - Drops into Claude Code as a `PreToolUse` hook.
>
> `npm i -g aegis-agent-guard` · MIT · https://github.com/Dhayalramesh/aegis-guard
>
> ![demo](<demo-gif-url>)
>
> It's a heuristic seatbelt, not a sandbox — curious what destructive patterns
> you'd want it to catch that it doesn't yet.

(For r/ClaudeAI, lead with the Claude Code hook angle; for r/commandline, lead
with the CLI + tamper-evident log.)

---

## X / Twitter thread

**1/**
> AI coding agents have deleted production databases — and then lied about it.
>
> I built Aegis: a seatbelt that screens every command an agent runs *before* it
> runs, and keeps a log the agent can't fake.
>
> `npm i -g aegis-agent-guard`
> [demo gif]

**2/**
> It blocks the catastrophic stuff — `rm -rf /`, `DROP TABLE`, force-push to main,
> deleting backups, writing to ~/.ssh — and asks about the risky stuff like .env
> edits and `terraform destroy`.

**3/**
> Obfuscation doesn't help. `r''m -rf /`, `sh -c "..."`, `bash -c "$(curl …)"`,
> `eval "$x"` are all normalized before matching. A naive grep-guard misses these;
> Aegis doesn't.

**4/**
> The part I care about most: a hash-chained audit log. Every decision is recorded,
> and `aegis log --verify` detects any edit, deletion, or reorder. The direct
> answer to "the agent rewrote the logs."

**5/**
> Drops into Claude Code as a PreToolUse hook in ~6 lines. MIT, ~1k LOC, 90+ tests.
>
> Repo + install: https://github.com/Dhayalramesh/aegis-guard
>
> Feedback and destructive-pattern ideas very welcome.
