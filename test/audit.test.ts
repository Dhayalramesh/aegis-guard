import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { readLog, record, verify } from '../src/audit.js';

function tmpLog(): string {
  return join(mkdtempSync(join(tmpdir(), 'aegis-')), 'audit.log');
}

describe('audit log', () => {
  it('appends chained entries with increasing seq', () => {
    const log = tmpLog();
    record(log, { ts: '2026-01-01T00:00:00.000Z', command: 'ls', decision: 'allow', ruleIds: [] });
    record(log, { ts: '2026-01-01T00:00:01.000Z', command: 'rm -rf /', decision: 'block', ruleIds: ['fs.rm-rf-root'] });
    const entries = readLog(log);
    expect(entries).toHaveLength(2);
    expect(entries[0].seq).toBe(0);
    expect(entries[1].seq).toBe(1);
    expect(entries[1].prevHash).toBe(entries[0].hash);
  });

  it('verifies an intact chain', () => {
    const log = tmpLog();
    for (let i = 0; i < 5; i++) {
      record(log, { ts: `2026-01-01T00:00:0${i}.000Z`, command: `cmd ${i}`, decision: 'allow', ruleIds: [] });
    }
    expect(verify(log)).toMatchObject({ ok: true, count: 5 });
  });

  it('detects a tampered entry (the core anti-fabrication guarantee)', () => {
    const log = tmpLog();
    record(log, { ts: '2026-01-01T00:00:00.000Z', command: 'rm -rf /', decision: 'block', ruleIds: ['fs.rm-rf-root'] });
    record(log, { ts: '2026-01-01T00:00:01.000Z', command: 'ls', decision: 'allow', ruleIds: [] });

    // Simulate an agent editing the log to hide that it tried something destructive.
    const lines = readFileSync(log, 'utf8').trimEnd().split('\n');
    const forged = JSON.parse(lines[0]);
    forged.command = 'ls'; // rewrite the blocked command to look innocent
    lines[0] = JSON.stringify(forged);
    writeFileSync(log, lines.join('\n') + '\n');

    const v = verify(log);
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toBe(0);
  });

  it('detects a removed entry', () => {
    const log = tmpLog();
    record(log, { ts: '2026-01-01T00:00:00.000Z', command: 'a', decision: 'allow', ruleIds: [] });
    record(log, { ts: '2026-01-01T00:00:01.000Z', command: 'b', decision: 'allow', ruleIds: [] });
    record(log, { ts: '2026-01-01T00:00:02.000Z', command: 'c', decision: 'allow', ruleIds: [] });

    const lines = readFileSync(log, 'utf8').trimEnd().split('\n');
    lines.splice(1, 1); // delete the middle entry
    writeFileSync(log, lines.join('\n') + '\n');

    expect(verify(log).ok).toBe(false);
  });
});
