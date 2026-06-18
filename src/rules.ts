import type { Rule } from './types.js';

/**
 * Built-in danger rules.
 *
 * These are heuristics, not a sandbox. They are tuned to catch the catastrophic,
 * low-false-positive cases (block) and the "are you sure?" cases (confirm). They
 * are deliberately conservative: `block` is reserved for commands that are almost
 * never intentional in an automated context. Everything is overridable via .aegis.yml.
 *
 * Precedence at evaluation time is block > confirm > allow, so a command that
 * trips both a `confirm` and a `block` rule is blocked.
 */
export const BUILTIN_RULES: Rule[] = [
  // ── Filesystem destruction ────────────────────────────────────────────────
  {
    id: 'fs.rm-rf-root',
    description: 'Recursive force-delete targeting root, home, or a bare wildcard',
    // require a recursive flag AND a force flag somewhere, AND the final target is /, ~, $HOME, *, or .
    pattern: String.raw`\brm\b(?=[^\n]*-[a-zA-Z]*r)(?=[^\n]*-[a-zA-Z]*f)[^\n]*\s(?:/|~|\$HOME|\*|\.)\s*(?:$|[;&|])`,
    action: 'block',
    severity: 'critical',
    message: 'rm -rf targeting /, ~, $HOME, or * — refusing. This wipes entire trees.',
    tags: ['filesystem', 'destructive'],
  },
  {
    id: 'fs.rm-recursive-force',
    description: 'Any recursive force-delete',
    pattern: String.raw`\brm\b(?=[^\n]*-[a-zA-Z]*r)(?=[^\n]*-[a-zA-Z]*f)`,
    action: 'confirm',
    severity: 'high',
    message: 'Recursive, forced delete (rm -rf). Confirm the target path is intended.',
    tags: ['filesystem'],
  },
  {
    id: 'fs.disk-overwrite',
    description: 'Direct block-device overwrite (mkfs / dd / redirect to /dev/sdX)',
    pattern: String.raw`\bmkfs(\.\w+)?\b|\bdd\b[^\n]*\bof=/dev/|>\s*/dev/(?:sd|hd|nvme|disk|mmcblk)\w*`,
    action: 'block',
    severity: 'critical',
    message: 'Writing directly to a block device destroys the disk/partition.',
    tags: ['filesystem', 'destructive'],
  },
  {
    id: 'fs.fork-bomb',
    description: 'Classic shell fork bomb',
    pattern: String.raw`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`,
    action: 'block',
    severity: 'critical',
    message: 'Fork bomb detected — this will exhaust system resources.',
    tags: ['dos'],
  },
  {
    id: 'fs.chmod-recursive-broad',
    description: 'Recursive chmod over / or a wildcard',
    pattern: String.raw`\bchmod\b[^\n]*\s-[a-zA-Z]*R[^\n]*\s(?:/|\*)`,
    action: 'confirm',
    severity: 'high',
    message: 'Recursive permission change over a broad path. Confirm scope.',
    tags: ['filesystem'],
  },

  // ── Backups ───────────────────────────────────────────────────────────────
  {
    id: 'backup.delete',
    description: 'Deleting backups',
    pattern: String.raw`\b(?:rm|del|delete|drop|destroy)\b[^\n]*\bback[\s_-]?ups?\b`,
    action: 'block',
    severity: 'critical',
    message: 'Deleting backups removes your recovery path. Refusing by default.',
    tags: ['backup', 'destructive'],
  },

  // ── Git destructive ───────────────────────────────────────────────────────
  {
    id: 'git.force-push-protected',
    description: 'Force-push to a protected branch (main/master/prod/release)',
    pattern: String.raw`\bgit\s+push\b[^\n]*(?:--force\b|--force-with-lease\b|\s-f\b)[^\n]*\b(?:main|master|prod|production|release)\b`,
    action: 'block',
    severity: 'critical',
    message: 'Force-pushing to a protected branch can erase shared history.',
    tags: ['git', 'destructive'],
  },
  {
    id: 'git.force-push',
    description: 'Force-push to any branch',
    pattern: String.raw`\bgit\s+push\b[^\n]*(?:--force\b|--force-with-lease\b|\s-f\b)`,
    action: 'confirm',
    severity: 'high',
    message: 'Force-push rewrites remote history. Confirm the branch.',
    tags: ['git'],
  },
  {
    id: 'git.reset-hard',
    description: 'git reset --hard discards uncommitted work',
    pattern: String.raw`\bgit\s+reset\b[^\n]*--hard`,
    action: 'confirm',
    severity: 'medium',
    message: 'git reset --hard permanently discards uncommitted changes.',
    tags: ['git'],
  },
  {
    id: 'git.clean-force',
    description: 'git clean -f deletes untracked files',
    pattern: String.raw`\bgit\s+clean\b[^\n]*\s-[a-zA-Z]*f`,
    action: 'confirm',
    severity: 'medium',
    message: 'git clean -f deletes untracked files irreversibly.',
    tags: ['git'],
  },
  {
    id: 'git.history-rewrite',
    description: 'History rewrite (filter-branch / mirror push)',
    pattern: String.raw`\bgit\s+filter-branch\b|\bgit\s+push\b[^\n]*--mirror`,
    action: 'confirm',
    severity: 'high',
    message: 'Rewriting or mirroring history can destroy commits for everyone.',
    tags: ['git'],
  },

  // ── Databases ─────────────────────────────────────────────────────────────
  {
    id: 'db.drop',
    description: 'DROP TABLE / DATABASE / SCHEMA',
    pattern: String.raw`\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b`,
    action: 'block',
    severity: 'critical',
    message: 'DROP removes a table/database/schema and its data. Refusing by default.',
    tags: ['database', 'destructive'],
  },
  {
    id: 'db.delete-no-where',
    description: 'DELETE FROM without a WHERE clause (mass delete)',
    pattern: String.raw`\bDELETE\s+FROM\b(?![^;\n]*\bWHERE\b)`,
    action: 'block',
    severity: 'critical',
    message: 'DELETE without WHERE removes every row. Add a WHERE clause or override.',
    tags: ['database', 'destructive'],
  },
  {
    id: 'db.update-no-where',
    description: 'UPDATE ... SET without a WHERE clause (mass update)',
    pattern: String.raw`\bUPDATE\s+[\w."` + '`' + String.raw`\[\]]+\s+SET\b(?![^;\n]*\bWHERE\b)`,
    action: 'confirm',
    severity: 'high',
    message: 'UPDATE without WHERE rewrites every row. Confirm intent.',
    tags: ['database'],
  },
  {
    id: 'db.truncate',
    description: 'TRUNCATE empties a table',
    pattern: String.raw`\bTRUNCATE\s+(?:TABLE\s+)?[\w."` + '`' + String.raw`\[\]]+`,
    action: 'confirm',
    severity: 'high',
    message: 'TRUNCATE empties a table (and cannot always be rolled back).',
    tags: ['database'],
  },

  // ── Cloud / infra destruction ─────────────────────────────────────────────
  {
    id: 'cloud.aws-s3-rm-recursive',
    description: 'Recursive S3 delete',
    pattern: String.raw`\baws\s+s3\s+rm\b[^\n]*--recursive`,
    action: 'block',
    severity: 'critical',
    message: 'Recursive S3 delete can wipe an entire bucket/prefix.',
    tags: ['cloud', 'destructive'],
  },
  {
    id: 'cloud.aws-delete',
    description: 'AWS delete-* operations',
    pattern: String.raw`\baws\s+\w[\w-]*\s+delete-[\w-]+`,
    action: 'confirm',
    severity: 'high',
    message: 'AWS delete operation. Confirm the target resource.',
    tags: ['cloud'],
  },
  {
    id: 'cloud.k8s-delete',
    description: 'kubectl delete',
    pattern: String.raw`\bkubectl\s+delete\b`,
    action: 'confirm',
    severity: 'high',
    message: 'kubectl delete removes live cluster resources.',
    tags: ['cloud', 'kubernetes'],
  },
  {
    id: 'cloud.terraform-destroy-auto',
    description: 'terraform destroy -auto-approve',
    pattern: String.raw`\bterraform\s+destroy\b[^\n]*-auto-approve`,
    action: 'block',
    severity: 'critical',
    message: 'terraform destroy -auto-approve tears down infra with no prompt.',
    tags: ['cloud', 'destructive'],
  },
  {
    id: 'cloud.terraform-destroy',
    description: 'terraform destroy',
    pattern: String.raw`\bterraform\s+destroy\b`,
    action: 'confirm',
    severity: 'high',
    message: 'terraform destroy tears down managed infrastructure.',
    tags: ['cloud'],
  },
  {
    id: 'cloud.volume-delete',
    description: 'Provider volume/backup deletion (Railway/Fly/Docker)',
    pattern: String.raw`\brailway\b[^\n]*\bdelete\b|\bfly\b[^\n]*volumes?\s+destroy|\bdocker\s+volume\s+rm\b`,
    action: 'block',
    severity: 'critical',
    message: 'Deleting a managed volume can erase a database and its backups.',
    tags: ['cloud', 'destructive'],
  },

  // ── Remote code execution / exfiltration ──────────────────────────────────
  {
    id: 'net.curl-pipe-shell',
    description: 'Piping a remote download straight into a shell',
    pattern: String.raw`\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python\d?)\b`,
    action: 'confirm',
    severity: 'high',
    message: 'curl|bash runs unaudited remote code. Confirm you trust the source.',
    tags: ['network', 'supply-chain'],
  },
  {
    id: 'net.env-exfil',
    description: 'Piping environment/secret files to the network',
    pattern: String.raw`\b(?:env|printenv|cat)\b[^\n]*(?:\.env|id_rsa|credentials|secrets?)?[^\n]*\|\s*(?:curl|wget|nc|ncat|telnet)\b`,
    action: 'block',
    severity: 'critical',
    message: 'This pipes environment/secret data to a remote host (exfiltration).',
    tags: ['network', 'secrets'],
  },

  // ── Publish / release ─────────────────────────────────────────────────────
  {
    id: 'release.npm-publish',
    description: 'npm publish',
    pattern: String.raw`\bnpm\s+publish\b`,
    action: 'confirm',
    severity: 'medium',
    message: 'npm publish pushes a package to the public registry.',
    tags: ['release'],
  },
  {
    id: 'release.pypi-upload',
    description: 'twine upload (PyPI)',
    pattern: String.raw`\btwine\s+upload\b`,
    action: 'confirm',
    severity: 'medium',
    message: 'twine upload publishes a package to PyPI.',
    tags: ['release'],
  },

  // ── System ────────────────────────────────────────────────────────────────
  {
    id: 'sys.power',
    description: 'Shutdown / reboot / halt',
    pattern: String.raw`\b(?:shutdown|reboot|halt|poweroff)\b`,
    action: 'confirm',
    severity: 'medium',
    message: 'Power-state change (shutdown/reboot).',
    tags: ['system'],
  },
];
