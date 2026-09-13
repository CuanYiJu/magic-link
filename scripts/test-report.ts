/**
 * Runs the test suite through node:test's programmatic runner and writes
 * test-report.html: a page a human can read to review what is verified.
 *
 *   npm run test:report
 *
 * The page has three parts: the plan rules each test proves, every test
 * case with its result, and a manual acceptance checklist for the demo.
 */
import { run } from 'node:test';
import { readdirSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const testDir = path.join(root, 'test');
const files = readdirSync(testDir)
  .filter((f) => f.endsWith('.test.ts'))
  .sort()
  .map((f) => path.join(testDir, f));

interface Case {
  file: string;
  name: string;
  ok: boolean;
  durationMs: number;
  error?: string;
}

const cases: Case[] = [];
const stream = run({ files, concurrency: true });
stream.on('test:pass', (e) => record(e, true));
stream.on('test:fail', (e) => record(e, false));
// Drain the stream; without a consumer it never finishes.
for await (const _ of stream) { /* events handled above */ }

function record(e: { name: string; file?: string; nesting: number; details: { duration_ms: number; error?: Error } }, ok: boolean) {
  const file = path.basename(e.file ?? 'unknown');
  // node:test reports each file as a top-level test too; keep only the cases inside.
  if (e.name.endsWith('.test.ts') || e.name === e.file) return;
  const err = e.details.error;
  const entry: Case = { file, name: e.name, ok, durationMs: e.details.duration_ms };
  if (!ok && err) entry.error = String((err as { cause?: unknown }).cause ?? err.message ?? err);
  cases.push(entry);
}

// ---------- requirement coverage: plan rule → tests that prove it ----------

interface Requirement {
  rule: string;
  source: string;
  match: RegExp;
}

const REQUIREMENTS: Requirement[] = [
  { rule: '邮箱 magic link 登录，一封邮件同时带链接与 6 位码', source: '计划书 4.2', match: /carrying a link and a 6-digit code|subject carries/ },
  { rule: '链接 15 分钟有效', source: '计划书 4.2', match: /expire after 15 minutes|one second before expiry/ },
  { rule: '链接单次使用', source: '计划书 4.2', match: /logs in exactly once|maps failures to status codes/ },
  { rule: '6 位码是链接的等价物（微信内使用），用其一另一个作废', source: '计划书 4.2', match: /burns the (link|code) from the same email/ },
  { rule: '6 位码错误次数上限，超过后作废', source: '计划书 5.6 认证安全', match: /five wrong codes|too many wrong codes/ },
  { rule: '同一邮箱 10 分钟最多 3 封、每天最多 10 封', source: '计划书 4.2', match: /per-email (rate limit|daily cap)/ },
  { rule: '登录与验证接口按 IP 限流', source: '计划书 5.6', match: /per-IP limit|rate limited per IP|rate limited request/ },
  { rule: '会话 cookie 30 天，HttpOnly + Secure + SameSite=Lax', source: '计划书 4.2', match: /cookie has the attributes|lasts 30 days|expiry is exactly 30 days|serializeSessionCookie/ },
  { rule: '会话固定防护：登录时吊销旧会话', source: '计划书 5.6', match: /session fixation/ },
  { rule: 'CSRF：SameSite cookie + Origin 校验', source: '计划书 5.6 应用安全', match: /foreign Origin|Referer is accepted/ },
  { rule: '不存明文：token、6 位码、会话只存 HMAC', source: '安全设计', match: /never stored|raw token is not stored|hmac is deterministic/ },
  { rule: '邮件扫描器的 GET 不消耗链接', source: '安全设计', match: /does not consume the link/ },
  { rule: 'next 只接受站内路径（防开放重定向）', source: '安全设计', match: /open-redirect|resolveNextPath|safe next/ },
  { rule: '新用户首次登录进入 /onboarding', source: '计划书 4.1', match: /resolveNextPath|redirects to a safe next|returns redirectTo/ },
  { rule: '被封禁账号不能登录', source: '计划书 5.3 users.status', match: /banned users|canLogin is false/ },
  { rule: '退出登录吊销会话并清 cookie', source: '计划书 4.1 设置页', match: /logout (revokes|clears)/ },
  { rule: '所有输入经 zod 校验，SQL 全部参数化', source: '计划书 5.6 应用安全', match: /garbage tokens|malformed addresses|no inlined literals|maps rows to records/ },
  { rule: 'Postgres 存储的原子消耗与并发创建用户', source: '实现', match: /consume only succeeds|racing insert/ },
  { rule: '过期数据清理（Cron）', source: '计划书 5.2 后台任务', match: /purgeExpired/ },
  { rule: '邮件文案：中文为主、含英文一句、转义', source: '计划书 4.14', match: /text and html both contain|escapes attacker-influenced/ },
];

// ---------- render ----------

const passed = cases.filter((c) => c.ok).length;
const failed = cases.length - passed;
const totalMs = cases.reduce((s, c) => s + c.durationMs, 0);
const byFile = new Map<string, Case[]>();
for (const c of cases) byFile.set(c.file, [...(byFile.get(c.file) ?? []), c]);

let commit = 'uncommitted';
try {
  commit = execSync('git -c safe.directory=* rev-parse --short HEAD', { cwd: root, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
} catch { /* no repo yet */ }

const FILE_LABELS: Record<string, string> = {
  'service.test.ts': '核心流程 service.ts',
  'http.test.ts': 'HTTP 处理器 http.ts',
  'session.test.ts': '会话与 cookie session.ts',
  'rate-limit.test.ts': '限流 rate-limit.ts',
  'crypto.test.ts': '随机数与哈希 crypto.ts',
  'email-template.test.ts': '登录邮件 email-template.ts',
  'postgres.test.ts': 'Postgres 存储 stores/postgres.ts',
};

const CHECKLIST = [
  ['启动', '`npm run dev`，打开 http://localhost:3000/login，页面显示邮箱输入框。'],
  ['发送', '输入邮箱提交，页面提示"邮件已发送"，终端打印一封邮件：标题含 6 位码，正文含链接与同一个 6 位码。'],
  ['链接登录', '复制终端里的链接到浏览器：先看到"正在登录…"页并自动跳转；新用户落在 /onboarding，返回首页显示"已登录"与用户 ID。'],
  ['链接只用一次', '再次打开同一链接，收到 410 与提示"这个链接已经用过了"。'],
  ['6 位码登录', '重新发送一封；在登录页输入 6 位码（可带空格），直接进入站内，不经过邮件客户端。'],
  ['错码保护', '连续输错 5 次，第 5 次返回 429"错误次数太多"；之后正确的码与同封邮件的链接都失效。'],
  ['限流', '同一邮箱 10 分钟内第 4 次发送返回 429，响应带 Retry-After。'],
  ['过期', '把 `linkTtlMs` 临时改小或等 15 分钟，链接与码都返回"已过期"。'],
  ['退出', '首页点"退出登录"，回到未登录状态；浏览器里的旧 cookie 再访问 /auth/me 得 401。'],
  ['跨站', '用 curl 带 `Origin: https://evil.test` POST /auth/magic-link，得 403。'],
  ['重定向', '带 `next=https://evil.test` 登录，落在首页而不是外站。'],
  ['邮件观感', '用 Resend 真实发一封到手机：微信通知栏能看到标题里的 6 位码；邮件在深色模式下可读。'],
];

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
const inlineCode = (s: string) => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');
const ms = (n: number) => (n < 1 ? '<1' : n.toFixed(n < 10 ? 1 : 0)) + ' ms';

const coverageRows = REQUIREMENTS.map((r) => {
  const hits = cases.filter((c) => r.match.test(c.name));
  const ok = hits.length > 0 && hits.every((c) => c.ok);
  const state = hits.length === 0 ? 'none' : ok ? 'pass' : 'fail';
  const label = hits.length === 0 ? '无测试' : ok ? '通过' : '失败';
  return `<tr>
  <td><span class="pill pill-${state}">${label}</span></td>
  <td>${esc(r.rule)}</td>
  <td class="muted">${esc(r.source)}</td>
  <td class="mono small">${hits.map((c) => `<div>${esc(c.name)}</div>`).join('') || '—'}</td>
</tr>`;
}).join('\n');

const fileSections = [...byFile.entries()].map(([file, list]) => {
  const fails = list.filter((c) => !c.ok).length;
  const rows = list.map((c) => `<li class="case ${c.ok ? 'ok' : 'bad'}">
  <span class="mark" aria-label="${c.ok ? '通过' : '失败'}">${c.ok ? '✓' : '✕'}</span>
  <span class="name">${esc(c.name)}</span>
  <span class="dur mono">${ms(c.durationMs)}</span>
  ${c.error ? `<pre class="err">${esc(c.error)}</pre>` : ''}
</li>`).join('\n');
  return `<details open>
  <summary><span class="file mono">${esc(file)}</span><span class="file-label">${esc(FILE_LABELS[file] ?? '')}</span><span class="count ${fails ? 'bad' : ''}">${list.length - fails}/${list.length}</span></summary>
  <ul class="cases">${rows}</ul>
</details>`;
}).join('\n');

const checklist = CHECKLIST.map(([title, body], i) => `<li>
  <label><input type="checkbox" data-key="ml-check-${i}"><span><strong>${esc(title!)}</strong> ${inlineCode(body!)}</span></label>
</li>`).join('\n');

const now = new Date();
const stamp = now.toLocaleString('zh-CN', { timeZone: 'America/Toronto', hour12: false });

const html = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>开局登录测试报告</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap">
<style>
:root {
  --bg: #F6F8F5; --surface: #FFFFFF; --ink: #1A1F1B; --muted: #5F6862; --line: #D8DED9;
  --accent: #1E6B47; --accent-soft: #E3F0E8; --bad: #B42318; --bad-soft: #FBE9E7; --none: #8A6D1A; --none-soft: #F7EFD6;
  --sans: "IBM Plex Sans", -apple-system, "PingFang SC", "Microsoft YaHei", "Noto Sans CJK SC", sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, "SFMono-Regular", Menlo, "PingFang SC", "Microsoft YaHei", monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #131714; --surface: #1B201C; --ink: #E7ECE8; --muted: #9AA59D; --line: #2E3630;
    --accent: #5FBF8E; --accent-soft: #1C3328; --bad: #F08A80; --bad-soft: #3B1F1C; --none: #D9B45A; --none-soft: #3A3120;
  }
}
:root[data-theme="dark"] {
  --bg: #131714; --surface: #1B201C; --ink: #E7ECE8; --muted: #9AA59D; --line: #2E3630;
  --accent: #5FBF8E; --accent-soft: #1C3328; --bad: #F08A80; --bad-soft: #3B1F1C; --none: #D9B45A; --none-soft: #3A3120;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font-family: var(--sans); font-size: 15px; line-height: 1.55; }
main { max-width: 76ch; margin: 0 auto; padding: 40px 20px 80px; display: flex; flex-direction: column; gap: 40px; }
h1, h2 { text-wrap: balance; margin: 0; font-weight: 600; letter-spacing: -0.01em; }
h1 { font-size: 26px; }
h2 { font-size: 18px; padding-bottom: 8px; border-bottom: 1px solid var(--line); }
p { margin: 0; max-width: 65ch; }
.eyebrow { font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); }
.muted { color: var(--muted); }
.small { font-size: 13px; }
.mono { font-family: var(--mono); font-variant-numeric: tabular-nums; }
code { font-family: var(--mono); font-size: 0.92em; background: var(--accent-soft); padding: 1px 5px; border-radius: 3px; }
header { display: flex; flex-direction: column; gap: 10px; }
.meta { display: flex; flex-wrap: wrap; gap: 6px 20px; font-size: 13px; color: var(--muted); }
.figures { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; background: var(--line); border: 1px solid var(--line); }
.figure { background: var(--surface); padding: 14px 16px; display: flex; flex-direction: column; gap: 2px; }
.figure .n { font-size: 28px; font-weight: 600; font-variant-numeric: tabular-nums; line-height: 1.1; }
.figure .n.bad { color: var(--bad); }
.figure .n.ok { color: var(--accent); }
.figure .l { font-size: 12px; color: var(--muted); }
section { display: flex; flex-direction: column; gap: 14px; }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th { text-align: left; font-weight: 500; font-size: 12px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); padding: 6px 10px; border-bottom: 1px solid var(--line); }
td { padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
td.mono { font-size: 12px; color: var(--muted); }
.pill { display: inline-block; font-size: 12px; font-weight: 500; padding: 2px 8px; border-radius: 999px; white-space: nowrap; }
.pill-pass { background: var(--accent-soft); color: var(--accent); }
.pill-fail { background: var(--bad-soft); color: var(--bad); }
.pill-none { background: var(--none-soft); color: var(--none); }
details { border: 1px solid var(--line); background: var(--surface); }
summary { cursor: pointer; padding: 10px 14px; display: flex; gap: 14px; align-items: baseline; list-style: none; }
summary::-webkit-details-marker { display: none; }
summary::before { content: "▸"; color: var(--muted); font-size: 12px; }
details[open] summary::before { content: "▾"; }
summary .file { font-size: 13px; font-weight: 500; }
summary .file-label { color: var(--muted); font-size: 13px; flex: 1; }
summary .count { font-family: var(--mono); font-size: 13px; color: var(--accent); }
summary .count.bad { color: var(--bad); }
.cases { list-style: none; margin: 0; padding: 0 14px 10px; display: flex; flex-direction: column; }
.case { display: grid; grid-template-columns: 18px 1fr auto; gap: 10px; padding: 6px 0; border-top: 1px solid var(--line); font-size: 14px; align-items: baseline; }
.case .mark { font-weight: 600; color: var(--accent); }
.case.bad .mark { color: var(--bad); }
.case .dur { font-size: 12px; color: var(--muted); }
.err { grid-column: 2 / -1; margin: 4px 0 0; padding: 8px 10px; background: var(--bad-soft); color: var(--ink); font-family: var(--mono); font-size: 12px; white-space: pre-wrap; overflow-x: auto; }
.checks { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 2px; counter-reset: step; }
.checks li { border-top: 1px solid var(--line); }
.checks li:last-child { border-bottom: 1px solid var(--line); }
.checks label { display: grid; grid-template-columns: 22px 1fr; gap: 12px; padding: 10px 4px; cursor: pointer; align-items: start; }
.checks input { width: 16px; height: 16px; margin-top: 3px; accent-color: var(--accent); }
.checks input:checked + span { color: var(--muted); }
.checks strong { font-weight: 600; margin-right: 6px; }
.checks input:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
footer { font-size: 13px; color: var(--muted); border-top: 1px solid var(--line); padding-top: 14px; }
@media (max-width: 560px) { .figures { grid-template-columns: repeat(2, 1fr); } .case { grid-template-columns: 18px 1fr; } .case .dur { grid-column: 2; } }
</style>
</head>
<body>
<main>
  <header>
    <div class="eyebrow">开局 · magic-link · 自动化测试报告</div>
    <h1>无密码登录：${failed === 0 ? '全部通过' : `${failed} 项失败`}</h1>
    <p>下面第一张表把计划书 4.2 / 5.6 的每条规则对应到证明它的测试；第二部分是每个测试文件的逐条结果；最后是需要人手动走一遍的验收清单。</p>
    <div class="meta">
      <span>生成时间 ${esc(stamp)}（多伦多）</span>
      <span>提交 <span class="mono">${esc(commit)}</span></span>
      <span>Node ${esc(process.version)}</span>
      <span>运行方式 <span class="mono">npm run test:report</span></span>
    </div>
  </header>

  <div class="figures" role="group" aria-label="汇总">
    <div class="figure"><span class="n">${cases.length}</span><span class="l">测试用例</span></div>
    <div class="figure"><span class="n ok">${passed}</span><span class="l">通过</span></div>
    <div class="figure"><span class="n ${failed ? 'bad' : ''}">${failed}</span><span class="l">失败</span></div>
    <div class="figure"><span class="n">${Math.round(totalMs)}<span class="small muted"> ms</span></span><span class="l">用例总耗时</span></div>
  </div>

  <section>
    <h2>规则覆盖</h2>
    <p class="muted small">"无测试"表示还没有自动化用例覆盖这条规则，需要在下面的人工清单里验证。</p>
    <div class="table-wrap">
    <table>
      <thead><tr><th>状态</th><th>规则</th><th>出处</th><th>证明它的测试</th></tr></thead>
      <tbody>
${coverageRows}
      </tbody>
    </table>
    </div>
  </section>

  <section>
    <h2>逐条结果</h2>
${fileSections}
  </section>

  <section>
    <h2>人工验收清单</h2>
    <p class="muted small">这些项靠眼睛和真实邮箱验证，自动化测不到。勾选状态只保存在你自己的浏览器里。</p>
    <ol class="checks">
${checklist}
    </ol>
  </section>

  <footer>报告由 <span class="mono">scripts/test-report.ts</span> 生成；测试文件在 <span class="mono">test/</span>，规则来源为《开局-项目计划书》。</footer>
</main>
<script>
(function () {
  var boxes = document.querySelectorAll('.checks input[type=checkbox]');
  boxes.forEach(function (b) {
    try { b.checked = localStorage.getItem(b.dataset.key) === '1'; } catch (e) {}
    b.addEventListener('change', function () {
      try { localStorage.setItem(b.dataset.key, b.checked ? '1' : '0'); } catch (e) {}
    });
  });
})();
</script>
</body>
</html>
`;

const out = path.join(root, 'test-report.html');
writeFileSync(out, html, 'utf8');
console.log(`${passed}/${cases.length} passed · report written to ${path.relative(process.cwd(), out)}`);
process.exitCode = failed ? 1 : 0;
