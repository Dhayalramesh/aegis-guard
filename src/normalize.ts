/**
 * Command normalization for evasion-resistant matching.
 *
 * Rules in this project match regexes against a command string. An agent (or a
 * compromised one) can dodge a naive match with shell tricks that the shell
 * itself collapses away before execution:
 *
 *   r''m -rf /          quote splitting        -> rm -rf /
 *   r\m -rf /           backslash escaping     -> rm -rf /
 *   "rm" -rf /          whole-token quoting    -> rm -rf /
 *   sh -c "rm -rf /"    nested-shell payload   -> sh -c rm -rf /
 *   rm -rf \<newline>/  line continuation      -> rm -rf /
 *
 * `normalizeCommand` produces the post-quote-removal view a shell would see, so
 * the same rules catch the disguised form. It is deliberately a *lightweight*
 * approximation of shell word-expansion — not a real parser, and it does not
 * resolve variables, globs, or command substitution. The evaluator treats a
 * match that appears *only* in the normalized view as advisory (it never
 * escalates such a match to a hard block) precisely because this pass can be
 * imprecise on quoted string literals.
 */

/**
 * Remove shell quoting/escaping and fold insignificant whitespace, returning the
 * string a shell would assemble after quote removal. Statement-separating
 * newlines are preserved (they bound several SQL rules); a backslash-newline
 * line continuation is joined.
 */
export function normalizeCommand(raw: string): string {
  const s = raw.replace(/\r\n/g, '\n');
  const out: string[] = [];
  let state: 'plain' | 'single' | 'double' = 'plain';

  for (let i = 0; i < s.length; i++) {
    const c = s[i];

    if (state === 'single') {
      if (c === "'") state = 'plain';
      else out.push(c); // single quotes are fully literal — no escapes
      continue;
    }

    if (state === 'double') {
      if (c === '"') {
        state = 'plain';
      } else if (c === '\\') {
        // In double quotes a backslash only escapes " \ $ ` and newline.
        const next = s[i + 1];
        if (next === '\n') {
          i++; // line continuation — drop both
        } else if (next === '"' || next === '\\' || next === '$' || next === '`') {
          out.push(next);
          i++;
        } else {
          out.push('\\'); // literal backslash otherwise
        }
      } else {
        out.push(c);
      }
      continue;
    }

    // state === 'plain'
    if (c === '\\') {
      const next = s[i + 1];
      if (next === undefined) break; // trailing backslash — drop
      if (next === '\n') {
        i++; // line continuation — join lines
      } else {
        out.push(next); // escaped char becomes literal; backslash removed
        i++;
      }
    } else if (c === "'") {
      state = 'single';
    } else if (c === '"') {
      state = 'double';
    } else {
      out.push(c);
    }
  }

  // Collapse spaces/tabs but keep newlines as statement boundaries.
  return out.join('').replace(/[ \t\f\v]+/g, ' ').replace(/ *\n */g, '\n').trim();
}
