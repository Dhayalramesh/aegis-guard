import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import yaml from 'js-yaml';
import { BUILTIN_RULES } from './rules.js';
import type { Policy, Rule } from './types.js';

export const POLICY_FILENAMES = ['.aegis.yml', '.aegis.yaml', 'aegis.yml'];

export function defaultPolicy(): Policy {
  return {
    version: 1,
    defaultAction: 'allow',
    useBuiltins: true,
    rules: [...BUILTIN_RULES],
  };
}

/** Find the nearest policy file walking up from `startDir` to the filesystem root. */
export function findPolicyFile(startDir: string): string | null {
  let dir = resolve(startDir);
  // eslint-disable-next-line no-constant-condition
  while (true) {
    for (const name of POLICY_FILENAMES) {
      const candidate = join(dir, name);
      if (existsSync(candidate)) return candidate;
    }
    const parent = resolve(dir, '..');
    if (parent === dir) return null;
    dir = parent;
  }
}

interface RawPolicy {
  version?: number;
  defaultAction?: Policy['defaultAction'];
  useBuiltins?: boolean;
  rules?: Rule[];
}

/**
 * Load the effective policy: user rules from the nearest .aegis.yml merged with
 * the built-in rules (unless `useBuiltins: false`). User rules come first so they
 * are reported first, but recall that block > confirm > allow precedence applies
 * regardless of order.
 */
export function loadPolicy(opts: { cwd: string; policyPath?: string }): { policy: Policy; source: string | null } {
  const file = opts.policyPath ?? findPolicyFile(opts.cwd);
  if (!file || !existsSync(file)) {
    return { policy: defaultPolicy(), source: null };
  }

  const raw = (yaml.load(readFileSync(file, 'utf8')) as RawPolicy) ?? {};
  const useBuiltins = raw.useBuiltins ?? true;
  const userRules = Array.isArray(raw.rules) ? raw.rules : [];

  const policy: Policy = {
    version: raw.version ?? 1,
    defaultAction: raw.defaultAction ?? 'allow',
    useBuiltins,
    rules: useBuiltins ? [...userRules, ...BUILTIN_RULES] : [...userRules],
  };
  return { policy, source: file };
}

export const STARTER_POLICY = `# .aegis.yml — Aegis Guard policy
# Docs: https://github.com/your-org/aegis
version: 1

# Decision when no rule matches. One of: allow | confirm | block
defaultAction: allow

# Merge Aegis's built-in danger rules (rm -rf /, DROP TABLE, force-push, etc.)
useBuiltins: true

# Your custom rules. Each rule matches via 'pattern' (regex) or 'any' (substrings).
# action is one of: allow | confirm | block
rules:
  - id: protect-prod-deploy
    description: Require confirmation before deploying to production
    any:
      - "deploy --env prod"
      - "deploy --env=production"
    action: confirm
    severity: high
    message: "Deploying to production — confirm intent."

  # Example allow-list override (lower precedence than block; for documentation):
  # - id: allow-local-rm-build
  #   description: Local build cleanup is fine
  #   pattern: 'rm -rf ./dist'
  #   action: allow
`;
