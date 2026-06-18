#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { join } from 'node:path';
import { Command } from 'commander';
import { readLog, record, verify } from './audit.js';
import { evaluate } from './evaluator.js';
import { loadPolicy, POLICY_FILENAMES, STARTER_POLICY } from './policy.js';
import type { Decision, EvalResult } from './types.js';

const VERSION = '0.1.0';

function logPath(cwd: string, override?: string): string {
  return override ?? process.env.AEGIS_LOG ?? join(cwd, '.aegis', 'audit.log');
}

function nowIso(): string {
  return new Date().toISOString();
}

/** Run evaluation + record an audit entry. Centralised so every entry path is logged. */
function assess(
  command: string,
  opts: { cwd: string; tool?: string; policyPath?: string; logFile?: string },
): { result: EvalResult; source: string | null } {
  const { policy, source } = loadPolicy({ cwd: opts.cwd, policyPath: opts.policyPath });
  const result = evaluate({ command, cwd: opts.cwd, tool: opts.tool }, policy);
  record(logPath(opts.cwd, opts.logFile), {
    ts: nowIso(),
    command,
    decision: result.decision,
    ruleIds: result.matched.map((m) => m.id),
    tool: opts.tool,
    cwd: opts.cwd,
  });
  return { result, source };
}

const ICON: Record<Decision, string> = { allow: '✓', confirm: '?', block: '✗' };

function printHuman(result: EvalResult, source: string | null): void {
  const stream = result.decision === 'allow' ? process.stdout : process.stderr;
  stream.write(`${ICON[result.decision]} ${result.reason}\n`);
  if (result.matched.length > 0) {
    for (const m of result.matched) {
      stream.write(`    · [${m.action}/${m.severity}] ${m.id} — ${m.message}\n`);
    }
  }
  if (source) stream.write(`    policy: ${source}\n`);
}

/** Map a decision to a process exit code: 0 allow, 1 confirm, 2 block. */
function exitCodeFor(decision: Decision): number {
  return decision === 'allow' ? 0 : decision === 'confirm' ? 1 : 2;
}

function readStdin(): Promise<string> {
  return new Promise((res) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (data += c));
    process.stdin.on('end', () => res(data));
    // If nothing is piped, don't hang forever.
    if (process.stdin.isTTY) res('');
  });
}

const program = new Command();
program
  .name('aegis')
  .description('A pre-commit safety guard for AI coding agents.')
  .version(VERSION);

program
  .command('init')
  .description('Write a starter .aegis.yml policy into the current directory')
  .option('-f, --force', 'overwrite an existing policy file')
  .action((opts: { force?: boolean }) => {
    const target = join(process.cwd(), POLICY_FILENAMES[0]);
    if (existsSync(target) && !opts.force) {
      process.stderr.write(`Refusing to overwrite existing ${POLICY_FILENAMES[0]} (use --force).\n`);
      process.exit(1);
    }
    writeFileSync(target, STARTER_POLICY);
    process.stdout.write(`Wrote ${target}\n`);
  });

program
  .command('check [command...]')
  .description('Evaluate a command against the policy (does not run it)')
  .option('--hook', 'read a Claude Code PreToolUse hook payload from stdin and emit a hook decision')
  .option('--json', 'print the evaluation result as JSON')
  .option('--cwd <dir>', 'working directory used to locate the policy', process.cwd())
  .option('--policy <file>', 'explicit policy file')
  .option('--log <file>', 'explicit audit log path')
  .action(async (commandParts: string[], opts: { hook?: boolean; json?: boolean; cwd: string; policy?: string; log?: string }) => {
    if (opts.hook) {
      await runHookMode(opts);
      return;
    }

    let command = commandParts.join(' ').trim();
    if (!command) command = (await readStdin()).trim();
    if (!command) {
      process.stderr.write('No command provided.\n');
      process.exit(2);
    }

    const { result, source } = assess(command, { cwd: opts.cwd, policyPath: opts.policy, logFile: opts.log });
    if (opts.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    } else {
      printHuman(result, source);
    }
    process.exit(exitCodeFor(result.decision));
  });

/**
 * Claude Code PreToolUse hook mode.
 *
 * Reads the hook JSON from stdin, extracts the Bash command, and emits a decision
 * via the documented `hookSpecificOutput` form (exit 0):
 *   - block   -> permissionDecision "deny"  (Claude refuses to run it)
 *   - confirm -> permissionDecision "ask"   (Claude prompts the human)
 *   - allow   -> no output, defer to Claude's normal permission flow
 */
async function runHookMode(opts: { cwd: string; policy?: string; log?: string }): Promise<void> {
  const payload = await readStdin();
  let command = '';
  let tool = 'Bash';
  let cwd = opts.cwd;
  try {
    const parsed = JSON.parse(payload) as {
      tool_name?: string;
      tool_input?: { command?: string };
      cwd?: string;
    };
    tool = parsed.tool_name ?? 'Bash';
    command = parsed.tool_input?.command ?? '';
    if (parsed.cwd) cwd = parsed.cwd;
  } catch {
    // Malformed payload: stay out of the way rather than break the agent.
    process.exit(0);
  }

  // Only guard shell commands; defer everything else.
  if (tool !== 'Bash' || !command.trim()) process.exit(0);

  const { result } = assess(command, { cwd, tool, policyPath: opts.policy, logFile: opts.log });

  if (result.decision === 'allow') {
    process.exit(0); // defer to normal permission flow
  }

  const permissionDecision = result.decision === 'block' ? 'deny' : 'ask';
  const output = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision,
      permissionDecisionReason: `aegis: ${result.reason}`,
    },
  };
  process.stdout.write(JSON.stringify(output) + '\n');
  process.exit(0);
}

program
  .command('run [command...]')
  .description('Evaluate, then run the command if allowed (confirm prompts on a TTY)')
  .option('--cwd <dir>', 'working directory', process.cwd())
  .option('--policy <file>', 'explicit policy file')
  .option('--log <file>', 'explicit audit log path')
  .option('-y, --yes', 'auto-approve confirm-level commands (non-interactive)')
  .action(async (commandParts: string[], opts: { cwd: string; policy?: string; log?: string; yes?: boolean }) => {
    const command = commandParts.join(' ').trim();
    if (!command) {
      process.stderr.write('No command provided.\n');
      process.exit(2);
    }

    const { result, source } = assess(command, { cwd: opts.cwd, policyPath: opts.policy, logFile: opts.log });
    printHuman(result, source);

    if (result.decision === 'block') {
      process.stderr.write('Refusing to run a blocked command.\n');
      process.exit(2);
    }

    if (result.decision === 'confirm' && !opts.yes) {
      const ok = await promptYesNo(`Run anyway? [y/N] `);
      if (!ok) {
        process.stderr.write('Aborted.\n');
        process.exit(1);
      }
    }

    const child = spawnSync(command, { stdio: 'inherit', shell: true, cwd: opts.cwd });
    process.exit(child.status ?? 0);
  });

program
  .command('log')
  .description('Show the audit log')
  .option('--verify', 'verify the tamper-evident hash chain')
  .option('--tail <n>', 'show only the last N entries', (v) => parseInt(v, 10))
  .option('--cwd <dir>', 'working directory', process.cwd())
  .option('--log <file>', 'explicit audit log path')
  .action((opts: { verify?: boolean; tail?: number; cwd: string; log?: string }) => {
    const file = logPath(opts.cwd, opts.log);
    if (opts.verify) {
      const v = verify(file);
      if (v.ok) {
        process.stdout.write(`✓ audit chain intact — ${v.count} entr${v.count === 1 ? 'y' : 'ies'} verified.\n`);
        process.exit(0);
      }
      process.stderr.write(`✗ audit chain TAMPERED at seq ${v.brokenAt}: ${v.reason}\n`);
      process.exit(2);
    }

    let entries = readLog(file);
    if (opts.tail && opts.tail > 0) entries = entries.slice(-opts.tail);
    for (const e of entries) {
      process.stdout.write(`#${e.seq} ${e.ts} [${e.decision}] ${e.command}` + (e.ruleIds.length ? `  (${e.ruleIds.join(', ')})` : '') + '\n');
    }
  });

function promptYesNo(q: string): Promise<boolean> {
  if (!process.stdin.isTTY) return Promise.resolve(false);
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((res) => {
    rl.question(q, (ans) => {
      rl.close();
      res(/^y(es)?$/i.test(ans.trim()));
    });
  });
}

program.parseAsync(process.argv);
