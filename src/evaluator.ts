import type {
  Decision,
  EvalContext,
  EvalResult,
  MatchedRule,
  Policy,
  Rule,
  Severity,
} from './types.js';
import { normalizeCommand } from './normalize.js';

const DECISION_RANK: Record<Decision, number> = { allow: 0, confirm: 1, block: 2 };
const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

interface CompiledRule extends Rule {
  regex: RegExp;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Compile a rule's matcher into a RegExp, or return null if the rule has no matcher. */
function compile(rule: Rule): CompiledRule | null {
  let source = rule.pattern;
  if (!source && rule.any && rule.any.length > 0) {
    source = rule.any.map(escapeRegex).join('|');
  }
  if (!source) return null;
  try {
    return { ...rule, regex: new RegExp(source, rule.flags ?? 'i') };
  } catch {
    // A malformed user rule should never crash evaluation; skip it.
    return null;
  }
}

export function compilePolicy(policy: Policy): CompiledRule[] {
  const compiled: CompiledRule[] = [];
  for (const rule of policy.rules) {
    const c = compile(rule);
    if (c) compiled.push(c);
  }
  return compiled;
}

/**
 * Evaluate a command against a policy.
 *
 * Decision precedence is block > confirm > allow: the most restrictive matched
 * rule wins, so the guard fails safe. If nothing matches, the policy's
 * `defaultAction` (default: allow) is returned.
 */
export function evaluate(ctx: EvalContext, policy: Policy): EvalResult {
  const rules = compilePolicy(policy);
  const matched: MatchedRule[] = [];

  // Match against the raw command and, separately, a quote/escape-stripped view
  // so the same rules catch obfuscated commands (r''m, "rm", sh -c "...", etc.).
  // A rule that fires only on the normalized view is capped at `confirm`: the
  // normalization pass can be imprecise on quoted string literals, so it surfaces
  // a suspected evasion for review instead of hard-blocking it outright.
  const normalized = normalizeCommand(ctx.command);
  const normalizedDiffers = normalized !== ctx.command;

  for (const rule of rules) {
    const action = rule.action;
    const severity = rule.severity ?? 'medium';
    const baseMessage = rule.message ?? rule.description;

    if (rule.regex.test(ctx.command)) {
      matched.push({ id: rule.id, action, severity, message: baseMessage });
    } else if (normalizedDiffers && rule.regex.test(normalized)) {
      const capped: Decision = action === 'block' ? 'confirm' : action;
      matched.push({
        id: rule.id,
        action: capped,
        severity,
        message: `${baseMessage} (matched after de-obfuscating the command)`,
      });
    }
  }

  let decision: Decision = policy.defaultAction ?? 'allow';
  for (const m of matched) {
    if (DECISION_RANK[m.action] > DECISION_RANK[decision]) decision = m.action;
  }

  // Surface the highest-severity rule that drove the decision.
  const drivers = matched
    .filter((m) => m.action === decision)
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);

  let reason: string;
  if (decision === 'allow') {
    reason = matched.length
      ? `Allowed (matched ${matched.length} informational rule(s)).`
      : 'Allowed — no rule matched.';
  } else {
    const top = drivers[0];
    const verb = decision === 'block' ? 'Blocked' : 'Needs confirmation';
    reason = top ? `${verb} by ${top.id}: ${top.message}` : `${verb} by policy default (${decision}).`;
  }

  return { decision, matched, reason };
}
