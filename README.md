# magic-link — 开局的无密码登录

计划书 §4.2 / §5.6 里定义的邮箱登录：一封邮件里同时带**链接**和 **6 位码**，二者等价、共用一次有效期；链接点开即登录，6 位码给在微信内置浏览器里报名、跳不回来的用户。没有密码，没有第三方 OAuth。

| 规则 | 值 | 来源 |
|---|---|---|
| 链接 / 6 位码有效期 | 15 分钟，单次使用，用了一个另一个作废 | §4.2 |
| 6 位码错误上限 | 5 次，超过后整封邮件（含链接）作废 | §5.6 认证安全 |
| 同一邮箱限流 | 10 分钟 3 封、每天 10 封 | §4.2（按验证码规则） |
| 同一 IP 限流 | 发送 10 分钟 10 次；验证 10 分钟 30 次 | §5.6 |
| 会话 cookie | 30 天，`HttpOnly; Secure; SameSite=Lax; Path=/` | §4.2 |
| 会话固定防护 | 登录成功时吊销浏览器原有会话、签发新 token | §5.6 |
| CSRF | SameSite cookie + `Origin`（退化到 `Referer`）校验 | §5.6 |
| 存储 | 只存 HMAC（链接、6 位码、会话 token 都不落库明文） | — |

## 目录

```
magic-link/
├── src/
│   ├── service.ts        核心：requestLink / verifyLink / verifyCode / getSession / logout
│   ├── session.ts        会话签发、解析、cookie 序列化
│   ├── http.ts           Fetch API 风格的路由处理器（Next.js Route Handler 可直接用）
│   ├── config.ts         配置与默认值，环境变量读取
│   ├── crypto.ts         随机 token / 6 位码、HMAC、常量时间比较
│   ├── rate-limit.ts     内存滑动窗口限流（接口可换 Postgres / Upstash 实现）
│   ├── email-template.ts 登录邮件（中文为主 + 一句英文）
│   ├── stores/memory.ts  内存存储（测试与本地演示）
│   ├── stores/postgres.ts Postgres 存储（pg / Drizzle 的 $client 直接可用）
│   ├── mailers/console.ts 打印到终端 / 捕获到内存
│   ├── mailers/resend.ts  Resend REST API
│   └── index.ts          公共导出
├── migrations/0001_magic_link.sql   auth_tokens、sessions 两张表
├── scripts/dev-server.ts            本地演示服务器（node:http）
└── test/                            node:test，不需要数据库
```

## 跑起来

需要 Node ≥ 22.18（直接运行 `.ts`，不用编译）。

```bash
cd magic-link && npm install
```

```bash
npm run check
```

`check` = `tsc --noEmit` + 43 个测试。本地演示：

```bash
npm run dev
```

打开 <http://localhost:3000/login>，输入邮箱；邮件会打印在终端里，点链接或在页面输入 6 位码都能登录。设置 `RESEND_API_KEY` 后改为真实发信（见 `.env.example`）。

## 接口

全部是 `POST` JSON（或表单），除了两个 `GET`。

| 方法 · 路径 | 请求 | 成功 | 失败 |
|---|---|---|---|
| `POST /auth/magic-link` | `{ email }` | `202 { status: "sent", email }`（邮箱不存在也返回 202，防枚举） | `400 invalid_email`、`429 rate_limited`（带 `Retry-After`）、`403 bad_origin` |
| `GET /auth/verify?token=…&next=…` | — | `200` HTML：自动提交的表单，把 token 以 POST 送回 | `400` |
| `POST /auth/verify` | `{ token, next? }` | `303` 到 `next`（新用户固定到 `/onboarding`），带 `Set-Cookie` | `400 invalid`、`410 expired / used`、`429`、`403 forbidden` |
| `POST /auth/verify-code` | `{ email, code, next? }` | `200 { status: "ok", redirectTo, isNew }`，带 `Set-Cookie` | 同上，另有 `429 too_many_attempts` |
| `POST /auth/logout` | — | `204`，清 cookie | `403 bad_origin` |
| `GET /auth/me` | — | `200 { userId, expiresAt }` | `401` |

失败响应都带一句中文 `message`，前端可直接展示或按 `status` 换成自己的文案。

**为什么 GET 不直接登录**：邮件服务商和企业安全网关会先替用户 GET 一遍链接。若 GET 就消耗 token，用户点开时链接已失效。所以 GET 只渲染一个自动提交的表单，真正消耗发生在 POST。

**`next` 只接受站内路径**：`/e/abc?x=1` 可以；`https://…`、`//host`、带反斜杠或换行的都会被换成默认路径，防开放重定向。

## 接进 Next.js（App Router）

```ts
// lib/auth.ts
import { Pool } from 'pg';
import {
  MagicLinkService, MemoryRateLimiter, PgSessionStore, PgTokenStore, PgUserStore,
  ResendMailer, configFromEnv, createHandlers,
} from '../../magic-link/src/index.ts';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
export const auth = new MagicLinkService({
  config: configFromEnv(),
  tokens: new PgTokenStore(pool),
  sessions: new PgSessionStore(pool),
  users: new PgUserStore(pool),
  mailer: new ResendMailer({ apiKey: process.env.RESEND_API_KEY! }),
  rateLimiter: new MemoryRateLimiter(),
});
export const handlers = createHandlers(auth, { trustProxy: true }); // Vercel 走代理
```

```ts
// app/auth/magic-link/route.ts
import { handlers } from '@/lib/auth';
export const POST = handlers.requestLink;

// app/auth/verify/route.ts
export const GET = handlers.verifyPage;
export const POST = handlers.verifyLink;

// app/auth/verify-code/route.ts → POST = handlers.verifyCode
// app/auth/logout/route.ts      → POST = handlers.logout
// app/auth/me/route.ts          → GET  = handlers.me
```

在 Server Component 或 middleware 里拿当前用户：

```ts
import { cookies } from 'next/headers';
const session = await auth.getSession((await cookies()).get(auth.config.cookieName)?.value);
```

建表：把 `migrations/0001_magic_link.sql` 交给 Drizzle 迁移或直接 `psql -f`。`users` 表由应用自己建（§5.3），`PgUserStore` 只用到 `id / email / created_at / last_login_at / status` 五列；列名不同时改 `stores/postgres.ts` 里的 `PgUserStore` 即可。

定时清理（Vercel Cron 每天一次）：`await auth.purgeExpired()`。

## 环境变量

见 [`.env.example`](.env.example)。`MAGIC_LINK_SECRET` 至少 32 个字符，轮换后所有会话与未用的链接一起失效。`APP_BASE_URL` 除 `localhost` 外必须是 `https`，否则启动报错；cookie 的 `Secure` 也由它决定。

## 还没做、故意留给应用层的

- **手机验证码（Twilio Verify）**：§4.2 的备选登录方式，本包只做邮箱。`UserStore` 已按"邮箱、手机至少一个"设计，不影响之后加。
- **登录页 UI**：`scripts/dev-server.ts` 里的页面只是演示；正式登录页在 Next.js 里做（微信内提示、复制链接按钮见 §5.7）。
- **多实例限流**：`MemoryRateLimiter` 单进程有效。Vercel 多区域或 Serverless 冷启动频繁时换成 Postgres 或 Upstash 实现 `RateLimiter` 接口（一个方法）。
- **管理后台 TOTP 二次验证**（§5.6）：与本包无关，单独做。
- **审计**：`auth_tokens` 记录了请求 IP 与 UA，`sessions` 记录了登录 IP、UA、最后活跃时间，够 §5.6 的泄露响应用；没有单独写 `audit_log`。
