import type { LoginResult, MagicLinkService, RequestContext } from './service.ts';
import { readCookie } from './session.ts';

/**
 * Framework-neutral handlers built on the Fetch API `Request` / `Response`.
 * In Next.js App Router each one is a Route Handler as-is:
 *
 *   // app/auth/magic-link/route.ts
 *   export const POST = handlers.requestLink;
 *
 * The dev server in scripts/ mounts the same handlers on node:http.
 */

export interface HttpOptions {
  /**
   * Trust `X-Forwarded-For` for the client IP. True on Vercel and behind any
   * reverse proxy you control; false when the app is reachable directly.
   */
  trustProxy: boolean;
  /**
   * Origins allowed to POST. Defaults to the app's baseUrl. Requests with a
   * different Origin are rejected, which with SameSite=Lax cookies is the
   * whole CSRF story for this service (§5.6).
   */
  allowedOrigins?: string[];
}

export interface MagicLinkHandlers {
  /** POST { email } → 202 { status: "sent" } (also for unknown addresses). */
  requestLink(req: Request): Promise<Response>;
  /** GET ?token=…&next=… → HTML page that POSTs the token (so mail scanners cannot consume it). */
  verifyPage(req: Request): Promise<Response>;
  /** POST { token, next? } (JSON or form) → 303 redirect with the session cookie, or 4xx JSON. */
  verifyLink(req: Request): Promise<Response>;
  /** POST { email, code, next? } → 200 JSON { redirectTo } with the session cookie, or 4xx JSON. */
  verifyCode(req: Request): Promise<Response>;
  /** POST → 204 with a cleared cookie. */
  logout(req: Request): Promise<Response>;
  /** GET → 200 { userId } or 401. Handy for the client to know if it is logged in. */
  me(req: Request): Promise<Response>;
  /** For your own routes: resolve the session from a request. */
  getSession(req: Request): Promise<{ userId: string } | null>;
}

const STATUS_CODES: Record<Exclude<LoginResult['status'], 'ok'>, number> = {
  invalid: 400,
  expired: 410,
  used: 410,
  too_many_attempts: 429,
  rate_limited: 429,
  forbidden: 403,
};

/** Chinese user-facing messages; the client may replace them with its own i18n. */
const MESSAGES: Record<Exclude<LoginResult['status'], 'ok'>, string> = {
  invalid: '链接或验证码无效，请重新发送登录邮件。',
  expired: '登录链接已过期（15 分钟有效），请重新发送。',
  used: '这个链接已经用过了，请重新发送登录邮件。',
  too_many_attempts: '验证码错误次数太多，请重新发送登录邮件。',
  rate_limited: '操作太频繁，请稍后再试。',
  forbidden: '这个账号暂时不能登录。',
};

export function createHandlers(service: MagicLinkService, options: HttpOptions): MagicLinkHandlers {
  const allowedOrigins = new Set(options.allowedOrigins ?? [service.config.baseUrl]);
  const cookieName = service.config.cookieName;

  const clientIp = (req: Request): string | null => {
    if (options.trustProxy) {
      const xff = req.headers.get('x-forwarded-for');
      if (xff) return xff.split(',')[0]?.trim() || null;
    }
    // Without a proxy the socket address is not visible through Request;
    // the dev server passes it in this header.
    return req.headers.get('x-magic-link-remote-addr');
  };

  const context = (req: Request): RequestContext => ({
    ip: clientIp(req),
    userAgent: req.headers.get('user-agent'),
    existingSessionToken: readCookie(req.headers.get('cookie'), cookieName),
  });

  const originOk = (req: Request): boolean => {
    const origin = req.headers.get('origin');
    if (origin) return allowedOrigins.has(origin);
    // Older WeChat webviews omit Origin on same-origin form posts; fall back to Referer.
    const referer = req.headers.get('referer');
    if (referer) {
      try {
        return allowedOrigins.has(new URL(referer).origin);
      } catch {
        return false;
      }
    }
    return false;
  };

  const readBody = async (req: Request): Promise<Record<string, string>> => {
    const type = req.headers.get('content-type') ?? '';
    if (type.includes('application/json')) {
      const data: unknown = await req.json().catch(() => null);
      if (!data || typeof data !== 'object') return {};
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(data)) if (typeof v === 'string') out[k] = v;
      return out;
    }
    if (type.includes('application/x-www-form-urlencoded') || type.includes('multipart/form-data')) {
      const form = await req.formData().catch(() => null);
      const out: Record<string, string> = {};
      if (form) for (const [k, v] of form.entries()) if (typeof v === 'string') out[k] = v;
      return out;
    }
    return {};
  };

  const failure = (result: Exclude<LoginResult, { status: 'ok' }>): Response => {
    const headers: Record<string, string> = {};
    if ('retryAfterMs' in result) headers['Retry-After'] = String(Math.ceil(result.retryAfterMs / 1000));
    return json({ status: result.status, message: MESSAGES[result.status] }, STATUS_CODES[result.status], headers);
  };

  return {
    async requestLink(req) {
      if (req.method !== 'POST') return methodNotAllowed('POST');
      if (!originOk(req)) return json({ status: 'bad_origin' }, 403);
      const body = await readBody(req);
      const result = await service.requestLink({ email: body.email ?? '', ...context(req) });
      switch (result.status) {
        case 'sent':
          return json({ status: 'sent', email: result.email }, 202);
        case 'invalid_email':
          return json({ status: 'invalid_email', message: '请输入正确的邮箱地址。' }, 400);
        case 'rate_limited':
          return json({ status: 'rate_limited', message: MESSAGES.rate_limited }, 429, {
            'Retry-After': String(Math.ceil(result.retryAfterMs / 1000)),
          });
      }
    },

    async verifyPage(req) {
      if (req.method !== 'GET') return methodNotAllowed('GET');
      const url = new URL(req.url);
      const token = url.searchParams.get('token') ?? '';
      const next = url.searchParams.get('next') ?? '';
      if (!token) return html(errorPage('链接不完整，请重新发送登录邮件。'), 400);
      return html(verifyPage(token, next, service.config.appName), 200);
    },

    async verifyLink(req) {
      if (req.method !== 'POST') return methodNotAllowed('POST');
      if (!originOk(req)) return json({ status: 'bad_origin' }, 403);
      const body = await readBody(req);
      const result = await service.verifyLink(body.token ?? '', context(req));
      if (result.status !== 'ok') return failure(result);
      const redirectTo = service.resolveNextPath(body.next, result.user);
      return new Response(null, {
        status: 303,
        headers: { Location: redirectTo, 'Set-Cookie': result.cookie, 'Cache-Control': 'no-store' },
      });
    },

    async verifyCode(req) {
      if (req.method !== 'POST') return methodNotAllowed('POST');
      if (!originOk(req)) return json({ status: 'bad_origin' }, 403);
      const body = await readBody(req);
      const result = await service.verifyCode(body.email ?? '', body.code ?? '', context(req));
      if (result.status !== 'ok') return failure(result);
      const redirectTo = service.resolveNextPath(body.next, result.user);
      return json({ status: 'ok', redirectTo, isNew: result.user.isNew }, 200, { 'Set-Cookie': result.cookie });
    },

    async logout(req) {
      if (req.method !== 'POST') return methodNotAllowed('POST');
      if (!originOk(req)) return json({ status: 'bad_origin' }, 403);
      const { cookie } = await service.logout(readCookie(req.headers.get('cookie'), cookieName));
      return new Response(null, { status: 204, headers: { 'Set-Cookie': cookie, 'Cache-Control': 'no-store' } });
    },

    async me(req) {
      const session = await service.getSession(readCookie(req.headers.get('cookie'), cookieName));
      if (!session) return json({ status: 'anonymous' }, 401);
      return json({ status: 'ok', userId: session.userId, expiresAt: session.session.expiresAt.toISOString() });
    },

    async getSession(req) {
      const session = await service.getSession(readCookie(req.headers.get('cookie'), cookieName));
      return session ? { userId: session.userId } : null;
    },
  };
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });
}

function html(body: string, status: number): Response {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Robots-Tag': 'noindex',
    },
  });
}

function methodNotAllowed(allow: string): Response {
  return new Response(null, { status: 405, headers: { Allow: allow } });
}

function escapeAttr(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
}

/**
 * Mail providers and corporate security gateways follow links with GET before
 * the user does. Consuming on GET would burn the single-use link before the
 * user sees it, so the GET renders a page that submits the token with POST.
 * With JavaScript the form submits itself; without it there is a button.
 */
function verifyPage(token: string, next: string, appName: string): string {
  const t = escapeAttr(token);
  const n = escapeAttr(next);
  const app = escapeAttr(appName);
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>登录 ${app}</title>
<style>
  body { margin: 0; padding: 48px 24px; font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", sans-serif; color: #1a1a1a; background: #f6f6f4; }
  main { max-width: 420px; margin: 0 auto; background: #fff; border-radius: 12px; padding: 32px; text-align: center; }
  button { font-size: 16px; padding: 12px 24px; border: 0; border-radius: 8px; background: #1a1a1a; color: #fff; cursor: pointer; }
  p { line-height: 1.6; }
</style>
</head>
<body>
<main>
  <h1 style="font-size:20px;margin:0 0 16px;">正在登录 ${app}…</h1>
  <form method="post" id="f">
    <input type="hidden" name="token" value="${t}">
    <input type="hidden" name="next" value="${n}">
    <p>如果页面没有自动跳转，点一下：</p>
    <button type="submit">继续登录</button>
  </form>
</main>
<script>document.getElementById('f').submit();</script>
</body>
</html>`;
}

function errorPage(message: string): string {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>登录失败</title></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'PingFang SC','Microsoft YaHei',sans-serif;padding:48px 24px;text-align:center;"><p>${escapeAttr(message)}</p><p><a href="/login">返回登录页</a></p></body></html>`;
}
