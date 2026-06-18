import { describe, expect, it } from 'vitest';
import { normalizeCommand } from '../src/normalize.js';

describe('normalizeCommand', () => {
  it.each([
    ["r''m -rf /", 'rm -rf /'],
    ["r'm' -rf /", 'rm -rf /'],
    ['r\\m -rf /', 'rm -rf /'],
    ['"rm" -rf /', 'rm -rf /'],
    ['rm  -rf   /', 'rm -rf /'],
    ['sh -c "rm -rf /"', 'sh -c rm -rf /'],
    ['rm -rf \\\n  /', 'rm -rf /'],
    ['echo "a   b"', 'echo a b'], // runs of whitespace are folded (incl. inside quotes)
    ["echo 'a   b'", 'echo a b'],
  ])('%s -> %s', (input, expected) => {
    expect(normalizeCommand(input)).toBe(expected);
  });

  it('leaves an already-plain command unchanged', () => {
    expect(normalizeCommand('git status')).toBe('git status');
  });

  it('preserves newlines as statement boundaries', () => {
    expect(normalizeCommand('SELECT 1\nDELETE FROM t')).toBe('SELECT 1\nDELETE FROM t');
  });
});
