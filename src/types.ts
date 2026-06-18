/** A decision about a proposed command. Ordered by severity: allow < confirm < block. */
export type Decision = 'allow' | 'confirm' | 'block';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

/**
 * What a rule's matcher is tested against:
 *   - `command` (default) — a shell command (Bash tool).
 *   - `path`              — the target file path of a write/edit (Write/Edit tools).
 *   - `content`          — the bytes being written into a file.
 * A rule only fires when the context actually carries that subject, so command
 * rules never trip on file edits and vice versa.
 */
export type Target = 'command' | 'path' | 'content';

/** A single policy rule. A rule matches via `pattern` (regex) or `any` (substrings). */
export interface Rule {
  id: string;
  description: string;
  /** Regex source, matched (case-insensitively by default) against the subject. */
  pattern?: string;
  /** Regex flags; defaults to 'i'. Ignored when `any` is used. */
  flags?: string;
  /** Convenience matcher: if any of these case-insensitive substrings appear, the rule fires. */
  any?: string[];
  /** Which part of the action this rule inspects. Defaults to 'command'. */
  target?: Target;
  /** What to do when this rule fires. */
  action: Decision;
  severity?: Severity;
  /** Human-readable explanation surfaced to the agent/human when the rule fires. */
  message?: string;
  tags?: string[];
}

export interface Policy {
  version: number;
  /** Decision when no rule matches. Defaults to 'allow'. */
  defaultAction: Decision;
  /** Merge the built-in rule set in addition to user rules. Defaults to true. */
  useBuiltins?: boolean;
  rules: Rule[];
}

export interface EvalContext {
  /** The shell command, for Bash actions. Empty for file operations. */
  command: string;
  /** Target file path, for Write/Edit actions. */
  path?: string;
  /** File contents being written, for Write/Edit actions. */
  content?: string;
  cwd?: string;
  tool?: string;
}

export interface MatchedRule {
  id: string;
  action: Decision;
  severity: Severity;
  message: string;
}

export interface EvalResult {
  decision: Decision;
  matched: MatchedRule[];
  /** One-line summary suitable for showing to a human or feeding back to an agent. */
  reason: string;
}
