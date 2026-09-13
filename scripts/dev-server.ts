/**
 * Local demo: `npm run dev`, open http://localhost:3000/login, submit an
 * email, read the link and code from the terminal, log in either way.
 * Uses in-memory stores and the console mailer unless RESEND_API_KEY is set.
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import {
  ConsoleMailer,
  MagicLinkService,
  MemoryRateLimiter,
  MemorySessionStore,
  MemoryTokenStore,
  MemoryUserStore,
  ResendMailer,
  createHandlers,
  resolveConfig,
} from '../src/index.ts';

const port = Number(process.env.PORT ?? 3000);
const config = resolveConfig({
  secret: process.env.MAGIC_LINK_SECRET ?? 'dev-only-secret-do-not-use-in-production-0123456789',
  baseUrl: process.env.APP_BASE_URL ?? `http://localhost:${port}`,
  emailFrom: process.env.EMAIL_FROM ?? '开局 <login@localhost>',
  appName: process.env.APP_NAME ?? '开局',
});

const service = new MagicLinkService({
  config,
  tokens: new MemoryTokenStore(),
  sessions: new MemorySessionStore(),
  users: new MemoryUserStore(),
  mailer: process.env.RESEND_API_KEY ? new ResendMailer({ apiKey: process.env.RESEND_API_KEY }) : new ConsoleMailer(),
  rateLimiter: new MemoryRateLimiter(),
});
const handlers = createHandlers(service, { trustProxy: false });

const routes: Record<string, (req: Request) => Promise<Response>> = {
  'POST /auth/magic-link': handlers.requestLink,
  'GET /auth/verify': handlers.verifyPage,
  'POST /auth/verify': handlers.verifyLink,
  'POST /auth/verify-code': handlers.verifyCode,
  'POST /auth/logout': handlers.logout,
  'GET /auth/me': handlers.me,
  'GET /login': async () => page(loginPage()),
  'GET /': async (req) => {
    const session = await handlers.getSession(req);
    return page(session ? homePage(session.userId) : `<p>未登录。<a href="/login">去登录</a></p>`);
  },
  'GET /onboarding': async (req) => {
    const session = await handlers.getSession(req);
    return page(session ? `<h1>欢迎，新用户 🎉</h1><p>这里是 /onboarding。</p><p><a href="/">首页</a></p>` : `<p>未登录。<a href="/login">去登录</a></p>`);
  },
};

const server = createServer(async (nodeReq, nodeRes) => {
  const req = toFetchRequest(nodeReq);
  const key = `${req.method} ${new URL(req.url).pathname}`;
  const handler = routes[key];
  const res = handler ? await handler(req).catch((err: unknown) => {
    console.error(err);
    return new Response('internal error', { status: 500 });
  }) : new Response('not found', { status: 404 });
  await writeFetchResponse(res, nodeRes);
});

server.listen(port, () => {
  console.log(`magic-link dev server → ${config.baseUrl}/login`);
});

function toFetchRequest(req: IncomingMessage): Request {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (Array.isArray(v)) v.forEach((x) => headers.append(k, x));
    else if (v) headers.set(k, v);
  }
  if (req.socket.remoteAddress) headers.set('x-magic-link-remote-addr', req.socket.remoteAddress);
  const method = req.method ?? 'GET';
  const hasBody = method !== 'GET' && method !== 'HEAD';
  const init: RequestInit & { duplex?: 'half' } = { method, headers };
  if (hasBody) {
    init.body = Readable.toWeb(req) as ReadableStream;
    init.duplex = 'half'; // Node requires this for streamed request bodies.
  }
  return new Request(url, init);
}

async function writeFetchResponse(res: Response, nodeRes: ServerResponse): Promise<void> {
  const headers: Record<string, string | string[]> = {};
  res.headers.forEach((v, k) => {
    if (k === 'set-cookie') headers[k] = res.headers.getSetCookie();
    else headers[k] = v;
  });
  nodeRes.writeHead(res.status, headers);
  nodeRes.end(res.body ? Buffer.from(await res.arrayBuffer()) : undefined);
}

function page(body: string): Response {
  return new Response(
    `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>开局 · dev</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;max-width:420px;margin:48px auto;padding:0 24px;line-height:1.6}input{font-size:16px;padding:8px;width:100%;box-sizing:border-box;margin:4px 0 12px}button{font-size:16px;padding:10px 20px}</style></head><body>${body}</body></html>`,
    { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } },
  );
}

function homePage(userId: string): string {
  return `<h1>已登录</h1><p>用户 ID：<code>${userId}</code></p>
<form method="post" action="/auth/logout"><button>退出登录</button></form>`;
}

function loginPage(): string {
  return `<h1>登录开局</h1>
<p>输入邮箱，我们发一封带链接和 6 位码的邮件（本地演示：邮件打印在终端里）。</p>
<form id="req"><label>邮箱<input name="email" type="email" required autocomplete="email"></label><button>发送登录邮件</button></form>
<p id="msg"></p>
<form id="code" hidden><p>在微信里打开的？直接输入邮件里的 6 位码：</p>
<input name="email" type="hidden"><label>验证码<input name="code" inputmode="numeric" pattern="[0-9 ]*" autocomplete="one-time-code" required></label><button>登录</button></form>
<script>
const msg = document.getElementById('msg');
const post = (url, body) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(async r => [r.status, await r.json()]);
document.getElementById('req').onsubmit = async (e) => {
  e.preventDefault();
  const email = e.target.email.value;
  const [status, data] = await post('/auth/magic-link', { email });
  msg.textContent = status === 202 ? '邮件已发送（看终端）。点邮件里的链接，或在下面输入 6 位码。' : (data.message || data.status);
  if (status === 202) { const f = document.getElementById('code'); f.hidden = false; f.email.value = email; }
};
document.getElementById('code').onsubmit = async (e) => {
  e.preventDefault();
  const [status, data] = await post('/auth/verify-code', { email: e.target.email.value, code: e.target.code.value });
  if (status === 200) location.href = data.redirectTo; else msg.textContent = data.message || data.status;
};
</script>`;
}
