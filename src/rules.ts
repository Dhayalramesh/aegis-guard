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
    id: 'fs.rm-recursive-var',
    description: 'Recursive delete whose target is an unresolved variable',
    // `rm -r` (force optional) where the args contain a $variable — the real
    // path is unknown at screen time, so it could expand to / or $HOME.
    pattern: String.raw`\brm\b(?=[^\n]*\s-[a-zA-Z]*r)(?=[^\n]*\$)`,
    action: 'confirm',
    severity: 'high',
    message: 'Recursive delete of a variable path ($VAR) — its value is unknown and could be / or $HOME.',
    tags: ['filesystem', 'indirection'],
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
    id: 'net.fetch-exec-substitution',
    description: 'Shell executing the output of a remote download via command substitution',
    // bash -c "$(curl ...)" / sh -c `wget ...` — runs whatever the URL returns.
    pattern: String.raw`\b(?:bash|sh|zsh|ksh|dash)\s+-c\b[^\n]*(?:\$\(|` + '`' + String.raw`)[^\n]*\b(?:curl|wget)\b`,
    action: 'confirm',
    severity: 'high',
    message: 'Executing the output of a remote download (bash -c "$(curl …)") runs unaudited code. Confirm the source.',
    tags: ['network', 'supply-chain', 'obfuscation'],
  },
  {
    id: 'net.decode-pipe-shell',
    description: 'Decoding (base64/xxd) piped straight into a shell or interpreter',
    pattern: String.raw`\b(?:base64|xxd|base32|openssl\s+(?:base64|enc))\b[^\n]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python\d?|perl|ruby|node)\b`,
    action: 'confirm',
    severity: 'high',
    message: 'Decoding data and piping it into a shell hides what is actually run. Confirm the source.',
    tags: ['network', 'supply-chain', 'obfuscation'],
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

  // ── File writes / edits (target: path) ────────────────────────────────────
  // These inspect the *destination path* of a Write/Edit, not a shell command.
  {
    id: 'file.ssh-key',
    description: 'Writing or editing an SSH private key',
    target: 'path',
    pattern: String.raw`(?:^|/)\.ssh/|(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)(?:$|[^/\w])`,
    action: 'block',
    severity: 'critical',
    message: 'Modifying SSH keys or ~/.ssh can hijack credentials. Refusing by default.',
    tags: ['filesystem', 'secrets'],
  },
  {
    id: 'file.system-path',
    description: 'Writing into an OS/system directory outside the project',
    target: 'path',
    pattern: String.raw`^/(?:etc|usr|bin|sbin|boot|lib|lib64|sys|proc|var/lib|System|Library)/`,
    action: 'block',
    severity: 'critical',
    message: 'Writing into a system directory can break or backdoor the machine.',
    tags: ['filesystem', 'destructive'],
  },
  {
    id: 'file.dotenv',
    description: 'Writing an environment/secrets file',
    target: 'path',
    // .env, .env.local, .env.production … but NOT .env.example/.sample/.template
    pattern: String.raw`(?:^|/)\.env(?:\.(?!example|sample|template|dist)[\w.-]+)?$`,
    action: 'confirm',
    severity: 'high',
    message: 'Editing a .env file can overwrite live secrets. Confirm intent.',
    tags: ['filesystem', 'secrets'],
  },
  {
    id: 'file.ci-config',
    description: 'Editing CI/CD pipeline configuration',
    target: 'path',
    pattern: String.raw`(?:^|/)\.github/workflows/|(?:^|/)\.gitlab-ci\.yml$|(?:^|/)\.circleci/|(?:^|/)Jenkinsfile$|(?:^|/)\.drone\.yml$`,
    action: 'confirm',
    severity: 'high',
    message: 'CI config runs with secrets and deploy access — a change here is a supply-chain risk.',
    tags: ['filesystem', 'supply-chain'],
  },
  {
    id: 'file.git-internal',
    description: 'Writing into the .git directory (history or hooks)',
    target: 'path',
    pattern: String.raw`(?:^|/)\.git/`,
    action: 'confirm',
    severity: 'high',
    message: 'Writing into .git can rewrite history or install a hook that runs on every commit.',
    tags: ['filesystem', 'git'],
  },
  {
    id: 'file.shell-rc',
    description: 'Editing a shell startup file (persistence vector)',
    target: 'path',
    pattern: String.raw`(?:^|/)\.(?:bashrc|bash_profile|zshrc|zprofile|profile|zshenv)$`,
    action: 'confirm',
    severity: 'medium',
    message: 'Shell startup files run on every new shell — a common persistence vector.',
    tags: ['filesystem', 'persistence'],
  },

  // ── File contents (target: content) ───────────────────────────────────────
  // These inspect the *bytes being written*, catching secrets committed to disk.
  {
    id: 'content.private-key',
    description: 'Writing a private key into a file',
    target: 'content',
    pattern: String.raw`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`,
    action: 'confirm',
    severity: 'high',
    message: 'The content contains a private key. Confirm you mean to write a secret to disk.',
    tags: ['secrets'],
  },
  {
    id: 'content.cloud-credential',
    description: 'Writing a cloud access key into a file',
    target: 'content',
    // AWS access key id, or a generic aws_secret_access_key assignment.
    pattern: String.raw`\bAKIA[0-9A-Z]{16}\b|\baws_secret_access_key\b\s*[=:]`,
    action: 'confirm',
    severity: 'high',
    message: 'The content looks like a cloud credential. Confirm before writing it to disk.',
    tags: ['secrets', 'cloud'],
  },

  // ── System ────────────────────────────────────────────────────────────────
  {
    id: 'sys.eval-dynamic',
    description: 'eval of dynamic content (variable or command substitution)',
    // `eval "$X"`, `eval $(...)`, eval `...` — executes a string assembled at
    // runtime, which Aegis cannot inspect ahead of time.
    pattern: String.raw`\beval\b[^\n]*(?:\$|` + '`' + String.raw`)`,
    action: 'confirm',
    severity: 'high',
    message: 'eval runs a string built at runtime ($var/$(...)) that cannot be screened in advance.',
    tags: ['system', 'indirection', 'obfuscation'],
  },
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
