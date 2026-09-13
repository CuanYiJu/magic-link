# magic-link — 开局的无密码登录

计划书 §4.2 / §5.6 里定义的邮箱登录：一封邮件里同时带**链接**和 **6 位码**，二者等价、共用一次有效期；链接点开即登录，6 位码给在微信内置浏览器里报名、跳不回来的用户。没有密码，没有第三方 OAuth。

| 规则 | 值 | 来源 |
|---|---|---|
| 链接 / 6 位码有效期 | 15 分钟，单次使用，用了一个另一个作废 | §4.2 |
| 6 位码错误上限 | 5 次，超过后整封邮件（含链接）作废 | §5.6 认证安全 |
| 同一邮箱限流 | 10 分钟 3 封、每天 10 封 | §4.2（按验证码规则） |
| 同一 IP 限流 | 发送 10 分钟 10 次；验证 10 分钟 30 次 | §5.6 |
| 会话 cookie | 30 天，`HttpOnly; Secure; SameSite=Lax; Path=/`，同时带 `Max-Age` 与 `Expires` | §4.2 |
| 会话滑动续期 | 30 天按"最后一次活跃"算：有访问就顺延，一天最多续一次并重发 cookie；从首次登录起最长 365 天 | §4.2 的实现选择 |
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
│   ├── mailers/smtp.ts    任何 SMTP 服务器（自建或托管商入口，nodemailer）
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

`check` = `tsc --noEmit` + 65 个测试。`npm run test:report` 会把结果渲染成 [`test-report.html`](test-report.html)（规则覆盖表 + 逐条结果 + 人工验收清单）。本地演示：

```bash
npm run dev
```

打开 <http://localhost:3000/login>，输入邮箱；邮件会打印在终端里，点链接或在页面输入 6 位码都能登录。设置 `RESEND_API_KEY` 或 `SMTP_HOST` 后改为真实发信（见下面「配置真实发信」）。

## 接口

全部是 `POST` JSON（或表单），除了两个 `GET`。

| 方法 · 路径 | 请求 | 成功 | 失败 |
|---|---|---|---|
| `POST /auth/magic-link` | `{ email }` | `202 { status: "sent", email }`（邮箱不存在也返回 202，防枚举） | `400 invalid_email`、`429 rate_limited`（带 `Retry-After`）、`403 bad_origin`、`503 send_failed`（邮件服务商拒收或故障，如 Resend 日限用完；带 `Retry-After: 120`，原因只写进服务器日志） |
| `GET /auth/verify?token=…&next=…` | — | `200` HTML：自动提交的表单，把 token 以 POST 送回 | `400` |
| `POST /auth/verify` | `{ token, next? }` | `303` 到 `next`（新用户固定到 `/onboarding`），带 `Set-Cookie` | `400 invalid`、`410 expired / used`、`429`、`403 forbidden` |
| `POST /auth/verify-code` | `{ email, code, next? }` | `200 { status: "ok", redirectTo, isNew }`，带 `Set-Cookie` | 同上，另有 `429 too_many_attempts` |
| `POST /auth/logout` | — | `204`，清 cookie | `403 bad_origin` |
| `GET /auth/me` | — | `200 { userId, expiresAt }`，刚续期时带新的 `Set-Cookie` | `401` |

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

**滑动续期需要 middleware 配合**：会话在服务端顺延后，浏览器里 cookie 的 `Max-Age` 还是登录时的值，所以 `getSession` 在刚续期时会带回一个 `setCookie`，把它加到响应头上即可（一天最多一次，其余时候是 `undefined`）。放在 middleware 里最省事，所有页面都覆盖：

```ts
// middleware.ts
import { NextResponse } from 'next/server';
import { handlers } from '@/lib/auth';

export async function middleware(req: Request) {
  const res = NextResponse.next();
  const session = await handlers.getSession(req);
  if (session?.setCookie) res.headers.append('Set-Cookie', session.setCookie);
  return res;
}
```

不想要滑动、坚持"登录后固定 30 天"：`resolveConfig({ ..., sessionSliding: false })`。

建表：把 `migrations/0001_magic_link.sql` 交给 Drizzle 迁移或直接 `psql -f`。`users` 表由应用自己建（§5.3），`PgUserStore` 只用到 `id / email / created_at / last_login_at / status` 五列；列名不同时改 `stores/postgres.ts` 里的 `PgUserStore` 即可。

定时清理（Vercel Cron 每天一次）：`await auth.purgeExpired()`。

## 环境变量

见 [`.env.example`](.env.example)。`MAGIC_LINK_SECRET` 至少 32 个字符，轮换后所有会话与未用的链接一起失效。`APP_BASE_URL` 除 `localhost` 外必须是 `https`，否则启动报错；cookie 的 `Secure` 也由它决定。

## 配置真实发信

代码里发信只依赖一个 `Mailer` 接口（一个 `send` 方法）。带了两种实现：`ResendMailer`（Resend 的 REST API）和 `SmtpMailer`（任何 SMTP 服务器，自建或托管商的 SMTP 入口都行）。演示服务器按环境变量选择：有 `RESEND_API_KEY` 走 Resend，否则有 `SMTP_HOST` 走 SMTP，都没有就打印到终端。

不管走哪条路，都要先做同一件事：**发信域名的 DNS**。

**第 0 步：域名的 SPF / DKIM / DMARC**

登录邮件要进收件箱，收件方（Gmail、Outlook、QQ）看的是三条 DNS 记录：SPF（哪些服务器可以替这个域名发信）、DKIM（邮件签名的公钥）、DMARC（前两条不通过时怎么处理）。用 Resend 时它会把要加的记录列出来；自建时要自己生成 DKIM 密钥并配置。三条都没有，邮件基本进垃圾箱或被拒收（计划书 6.4 上线清单里的 SPF / DKIM / DMARC 就是这一步）。

**路线 A：Resend（推荐，免费额度每天 100 封、每月 3,000 封）**

免费档的硬限制是**每天 100 封**（另有每月 3,000 封、3 个域名、日志保留 30 天、API 每秒 10 次）。每次登录请求就是一封邮件；会话 30 天，老用户大约一个月才登录一次，按基准情景的用户量平时远用不到，但一场被小红书带火的局可能一个下午带来 100+ 个新注册，超出后 Resend 直接拒收，接口返回 `503 send_failed`，用户看到"登录邮件暂时发不出去，请过几分钟再试"，服务器日志里有 Resend 的原文。上线周与推广的活动日盯着 resend.com/settings/usage；接近 100 就升 Pro（$20/月，50,000 封，不再有日限）。

1. 到 resend.com 注册，Domains 里添加域名（例如 `kaiju.example`），按它给的 DKIM / SPF / DMARC 记录到域名注册商处逐条添加，等状态变为 Verified。
2. API Keys 里建一把有发送权限的 key。
3. 域名还没验证时想先试：Resend 允许从 `onboarding@resend.dev` 发，但只能发给你 Resend 账号自己的邮箱。

`.env` 里填：

```
MAGIC_LINK_SECRET=<48 字节随机串，见下>
APP_BASE_URL=https://kaiju.example
EMAIL_FROM=开局 <login@kaiju.example>
RESEND_API_KEY=re_xxxxxxxxx
```

**路线 B：自建邮件服务器（SMTP）**

可以，但要清楚代价：发信的信誉绑在**服务器的 IP** 上。家庭宽带和多数云主机的 25 端口默认封禁，IP 段本身在黑名单里的也常见，而且反向 DNS（PTR）必须指回你的主机名。做得到这些再考虑自建；否则用托管商的 SMTP 入口（Resend、Postmark、SES、Mailgun 都提供），配置方式和自建完全一样，只是 `SMTP_HOST` 不同。

自建时的最小要求：

1. 一台有固定公网 IP、25 端口出站可用的主机，PTR 记录指向 `mail.kaiju.example`，正向解析也一致。
2. 装一个 MTA：Postfix + OpenDKIM，或一体化的 Mailcow / Stalwart / Maddy。给 `kaiju.example` 生成 DKIM 密钥，把公钥、SPF（`v=spf1 ip4:<你的IP> -all`）和 DMARC 写进 DNS。
3. 开一个提交端口给应用用：587（STARTTLS）或 465（TLS），配一个专用账号，只允许从 `login@kaiju.example` 发。不要开放式中继。
4. 用 mail-tester.com 发一封，分数 ≥ 9/10 再上线。

`.env` 里填：

```
MAGIC_LINK_SECRET=<48 字节随机串，见下>
APP_BASE_URL=https://kaiju.example
EMAIL_FROM=开局 <login@kaiju.example>
SMTP_HOST=mail.kaiju.example
SMTP_PORT=587
SMTP_USER=login@kaiju.example
SMTP_PASS=<账号密码>
```

同一台内网里、靠 IP 白名单免认证的中继：`SMTP_PORT=25`，`SMTP_USER` / `SMTP_PASS` 留空。自签证书的服务器加 `SMTP_REJECT_UNAUTHORIZED=false`，仅限自己控制的主机。

**路线 C：Cloudflare Email Service（不免费，Workers Paid $5/月）**

Cloudflare 2026 年起有了自己的发信服务（Email Sending，公测中），但**免费计划只能发给你账号里验证过的目标地址**（也就是你自己），给任意用户发需要 Workers Paid 计划：每月 $5，含 3,000 封，超出 $0.35 / 千封。域名已经在 Cloudflare 托管、又愿意付这 $5 的话，它的好处是 DNS 记录一键写入、DKIM 自动签名、日志在同一个后台。Resend 免费档同样是每月 3,000 封，所以只为发信不必为此付费。

它提供 SMTP 入口，用本包的 `SmtpMailer` 就能接，不用改代码：

1. Cloudflare 后台 Email Service → Email Sending 里 onboard 域名（记录会自动加进 Cloudflare DNS）。
2. 建一个 API token，权限 **Email Sending: Edit**。这个 token 就是 SMTP 密码，能用它从账号下任何域名发信，按密钥对待。

```
EMAIL_FROM=开局 <login@kaiju.example>
SMTP_HOST=smtp.mx.cloudflare.net
SMTP_PORT=465
SMTP_USER=api_token
SMTP_PASS=<Cloudflare API token>
```

只支持 465 隐式 TLS，不支持 587 STARTTLS；`SMTP_USER` 必须是字面量 `api_token`。`535` 是 token 权限或用户名不对，`550 Sender denied` 是发件域名没有 onboard。

另外两个容易混淆的 Cloudflare 免费功能与发信无关：Email Routing 是**收信**转发（免费、不限量）；Cloudflare DNS 免费托管域名，任何路线都可以用它来放 SPF / DKIM / DMARC 记录。

**Mailjet 的一个坑：发件地址没验证时，邮件被静默丢弃**

Mailjet 对没验证的发件地址不会在 SMTP 层报错：服务器照样回 250，本包返回 202，但邮件既不投递也不进 Mailjet 的消息记录。2026-09-13 实测：`EMAIL_FROM` 写成未验证的 `no-reply@juer.com` 时什么都收不到，改成域名已验证的 `login@juer.now` 后立刻 `sent`。所以 `EMAIL_FROM` 只能用「Sender addresses & domains」里状态为 Active 的地址（整个域名验证过的话任意前缀都行），换过发件地址后发一封测试并到 Mailjet 的 Statistics 里确认出现记录。Mailjet SMTP 参数：`in-v3.mailjet.com`，587（STARTTLS）或 465（TLS），用户名 = API Key，密码 = Secret Key。

**免费额度不够用时怎么办**

每天 100 封是 Resend 免费档的规则，不是邮件本身的限制。三个方向：花一点钱、换免费额度更高的服务商、少发。2026-09-13 核对的数字（Brevo 当天页面拒绝抓取，按其一贯政策填写，用前再看一眼）：

| 服务商 | 免费额度 | 第一档付费 |
|---|---|---|
| Resend | 每天 100 / 每月 3,000 | $20/月 50,000 封，无日限 |
| Mailjet | 每天 200 / 每月 6,000 | $9/月 8,000 封，去掉日限 |
| Amazon SES | 新账号 6 个月内 $200 抵扣 | 之后 $0.10 / 千封 |
| Brevo | 每天 300（待核对） | 约 $9/月 |
| Cloudflare Email Service | 无（只能发给自己验证过的地址） | $5/月 3,000 封 |

MVP 的建议：留在 Resend 免费档，上线周和推广活动日看用量。真的撞到日限，最便宜的长期解法是 **Amazon SES**：$0.10 / 千封，按乐观情景一年的登录邮件不到 $5，而且它提供 SMTP 入口，本包的 `SmtpMailer` 直接能接，不改代码。代价不是钱：要一个 AWS 账号、申请退出 SES 沙盒（通常一天内批）、以及和别家一样的 DNS 记录。

少发的办法（和换哪家都不冲突）：

- 会话已经是 30 天，老用户一个月才登录一次，不要缩短。
- 同一邮箱 10 分钟 3 封的限流已经挡住了连点"发送"造成的重复邮件。
- 计划书里的手机验证码登录接上 Twilio 后，用手机号的用户完全不占邮件额度。

不建议做的：把几家免费档叠起来自动切换（Resend 失败换 Mailjet）。技术上可行，但一个域名要配两套 DKIM、两个后台盯退信、发信信誉分散在两边，只为省 $9/月，不如直接付一家。

**三条路线共同的变量**

生成密钥：

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

- `EMAIL_FROM` 必须用配好 DNS 的域名，前面的显示名就是收件人看到的发件人。
- `APP_BASE_URL` 是邮件里链接指向的地址，必须是用户真的能打开的。本地用真实邮箱测试可以保留 `http://localhost:3000`，但链接只在跑服务器的这台机器上能点开。
- `MAGIC_LINK_SECRET` 至少 32 个字符；之后换掉会让所有人退出登录、所有未用的链接失效。

**用真实邮件跑本地演示**

演示服务器读的是 `process.env`，不会自己加载 `.env`，所以把文件交给 Node：

```bash
node --env-file=.env scripts/dev-server.ts
```

在登录页填自己的邮箱，几秒内应该收到。发送失败时服务器会打印原因：Resend 返回 HTTP 状态和错误正文（域名未验证、发件地址不在域名下、key 无效），SMTP 返回服务器的应答码（535 认证失败、550 拒绝中继、证书错误）。

**正式环境（Next.js / Vercel）**

配置用 `configFromEnv()`，邮件用 `new ResendMailer({ apiKey: process.env.RESEND_API_KEY! })` 或 `SmtpMailer.fromEnv()!`（见上面的接入示例）。Vercel 上把变量填进项目的 Environment Variables，不要提交 `.env`；密钥、key、SMTP 密码都不进 git。注意 Serverless 环境每次冷启动都会新建 SMTP 连接，对自建服务器意味着更多握手，量大时 Resend 这类 API 更省。

**发信通了之后的检查**

- 分别发一封到 Gmail、Outlook、QQ 邮箱，确认都不进垃圾箱。
- 头两周低量发信预热域名 / IP（计划书 6.4）。
- 看退信。登录邮件硬退信基本是地址打错，登录页可以提示用户检查。

## 还没做、故意留给应用层的

- **手机验证码（Twilio Verify）**：§4.2 的备选登录方式，本包只做邮箱。`UserStore` 已按"邮箱、手机至少一个"设计，不影响之后加。
- **登录页 UI**：`scripts/dev-server.ts` 里的页面只是演示；正式登录页在 Next.js 里做（微信内提示、复制链接按钮见 §5.7）。
- **多实例限流**：`MemoryRateLimiter` 单进程有效。Vercel 多区域或 Serverless 冷启动频繁时换成 Postgres 或 Upstash 实现 `RateLimiter` 接口（一个方法）。
- **管理后台 TOTP 二次验证**（§5.6）：与本包无关，单独做。
- **审计**：`auth_tokens` 记录了请求 IP 与 UA，`sessions` 记录了登录 IP、UA、最后活跃时间，够 §5.6 的泄露响应用；没有单独写 `audit_log`。
