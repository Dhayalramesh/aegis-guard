/** A decision about a proposed command. Ordered by severity: allow < confirm < block. */
export type Decision = 'allow' | 'confirm' | 'block';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

/** A single policy rule. A rule matches via `pattern` (regex) or `any` (substrings). */
export interface Rule {
  id: string;
  description: string;
  /** Regex source, matched (case-insensitively by default) against the full command. */
  pattern?: string;
  /** Regex flags; defaults to 'i'. Ignored when `any` is used. */
  flags?: string;
  /** Convenience matcher: if any of these case-insensitive substrings appear, the rule fires. */
  any?: string[];
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
  command: string;
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
