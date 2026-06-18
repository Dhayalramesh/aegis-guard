import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Decision } from './types.js';

const GENESIS = '0'.repeat(64);

export interface AuditEntry {
  seq: number;
  ts: string;
  tool?: string;
  command: string;
  cwd?: string;
  decision: Decision;
  ruleIds: string[];
  prevHash: string;
  hash: string;
}

/** The fields that are hashed, in a fixed key order, to form the chain. */
interface AuditBase {
  seq: number;
  ts: string;
  tool?: string;
  command: string;
  cwd?: string;
  decision: Decision;
  ruleIds: string[];
  prevHash: string;
}

function hashBase(base: AuditBase): string {
  return createHash('sha256').update(JSON.stringify(base)).digest('hex');
}

function readEntries(logPath: string): AuditEntry[] {
  if (!existsSync(logPath)) return [];
  return readFileSync(logPath, 'utf8')
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as AuditEntry);
}

/**
 * Append a record to the hash-chained audit log.
 *
 * Each entry's hash covers its own fields plus the previous entry's hash, so any
 * edit, deletion, or reordering of earlier entries invalidates every entry after
 * it. An agent cannot quietly rewrite history — `verify()` will catch it.
 */
export function record(
  logPath: string,
  input: {
    ts: string;
    command: string;
    decision: Decision;
    ruleIds: string[];
    tool?: string;
    cwd?: string;
  },
): AuditEntry {
  const entries = readEntries(logPath);
  const prev = entries[entries.length - 1];
  const base: AuditBase = {
    seq: prev ? prev.seq + 1 : 0,
    ts: input.ts,
    tool: input.tool,
    command: input.command,
    cwd: input.cwd,
    decision: input.decision,
    ruleIds: input.ruleIds,
    prevHash: prev ? prev.hash : GENESIS,
  };
  const entry: AuditEntry = { ...base, hash: hashBase(base) };

  mkdirSync(dirname(logPath), { recursive: true });
  appendFileSync(logPath, JSON.stringify(entry) + '\n');
  return entry;
}

export interface VerifyResult {
  ok: boolean;
  count: number;
  /** seq of the first entry whose hash or chain link is invalid, if any. */
  brokenAt?: number;
  reason?: string;
}

/** Recompute the chain and detect any tampering (edited, removed, or reordered entries). */
export function verify(logPath: string): VerifyResult {
  const entries = readEntries(logPath);
  let prevHash = GENESIS;

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.seq !== i) {
      return { ok: false, count: entries.length, brokenAt: e.seq, reason: `Unexpected seq ${e.seq} at position ${i}.` };
    }
    if (e.prevHash !== prevHash) {
      return { ok: false, count: entries.length, brokenAt: e.seq, reason: `Broken chain link at seq ${e.seq}.` };
    }
    const base: AuditBase = {
      seq: e.seq,
      ts: e.ts,
      tool: e.tool,
      command: e.command,
      cwd: e.cwd,
      decision: e.decision,
      ruleIds: e.ruleIds,
      prevHash: e.prevHash,
    };
    if (hashBase(base) !== e.hash) {
      return { ok: false, count: entries.length, brokenAt: e.seq, reason: `Hash mismatch at seq ${e.seq} (entry was modified).` };
    }
    prevHash = e.hash;
  }

  return { ok: true, count: entries.length };
}

export function readLog(logPath: string): AuditEntry[] {
  return readEntries(logPath);
}
