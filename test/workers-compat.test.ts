import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

/**
 * Cloudflare Workers has no `node:*` built-ins by default, no `process`, no
 * `Buffer`, and no nodemailer. Everything reachable from the main entry must
 * stay free of them so the package runs unchanged on Workers. The Node-only
 * SMTP mailer is deliberately kept out of that graph behind the './smtp' subpath.
 */

const srcDir = path.resolve(import.meta.dirname, '..', 'src');

function reachableFrom(entry: string): Set<string> {
  const seen = new Set<string>();
  const stack = [entry];
  while (stack.length) {
    const file = stack.pop() as string;
    if (seen.has(file)) continue;
    seen.add(file);
    const text = readFileSync(file, 'utf8');
    for (const m of text.matchAll(/from\s+'([^']+)'/g)) {
      const spec = m[1] as string;
      if (spec.startsWith('.')) stack.push(path.resolve(path.dirname(file), spec));
    }
  }
  return seen;
}

const banned: [RegExp, string][] = [
  [/from\s+'node:/, "node:* import"],
  [/\bimport\s+[^;]*from\s+'nodemailer'/, 'nodemailer import'],
  [/\bBuffer\./, 'Buffer'],
  [/\bprocess\.env\b/, 'process.env (use the env binding on Workers)'],
  [/\brequire\(/, 'require()'],
];

test('the main entry graph is free of Node-only APIs', () => {
  const files = reachableFrom(path.join(srcDir, 'index.ts'));
  assert.ok(files.size >= 10, `expected the whole package, saw ${files.size} files`);
  assert.ok(![...files].some((f) => f.endsWith('smtp.ts')), 'smtp.ts must not be reachable from index.ts');
  const offences: string[] = [];
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    for (const [re, label] of banned) {
      if (re.test(text)) offences.push(`${path.relative(srcDir, file)}: ${label}`);
    }
  }
  assert.deepEqual(offences, []);
});

test('the package exposes smtp only as a separate subpath', () => {
  const pkg = JSON.parse(readFileSync(path.resolve(srcDir, '..', 'package.json'), 'utf8')) as { exports: Record<string, string>; dependencies?: Record<string, string> };
  assert.equal(pkg.exports['.'], './src/index.ts');
  assert.equal(pkg.exports['./smtp'], './src/mailers/smtp.ts');
  assert.ok(!(pkg.dependencies ?? {})['nodemailer'], 'nodemailer must be an optional peer, not a hard dependency');
});

test('Web Crypto globals the package relies on exist here (as they do on Workers)', () => {
  assert.equal(typeof crypto.subtle.sign, 'function');
  assert.equal(typeof crypto.getRandomValues, 'function');
  assert.equal(typeof crypto.randomUUID, 'function');
  assert.equal(typeof Request, 'function');
  assert.equal(typeof Response, 'function');
  assert.equal(typeof TextEncoder, 'function');
});
