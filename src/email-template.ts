import type { EmailMessage } from './types.ts';

export interface LoginEmailInput {
  to: string;
  from: string;
  appName: string;
  link: string;
  code: string;
  /** Minutes until the link and code expire. */
  ttlMinutes: number;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
}

/**
 * Chinese first with a short English line, per plan §4.14. The 6-digit code
 * is in the subject so a user reading in WeChat can copy it from the
 * notification without opening the mail client (§4.2).
 */
export function renderLoginEmail(input: LoginEmailInput): EmailMessage {
  const app = escapeHtml(input.appName);
  const link = escapeHtml(input.link);
  const code = escapeHtml(input.code);
  const subject = `${input.appName} 登录验证码 ${input.code}`;

  const text = [
    `登录 ${input.appName}`,
    '',
    `点击链接登录（${input.ttlMinutes} 分钟内有效，只能用一次）：`,
    input.link,
    '',
    `在微信里打开的？回到登录页，输入这个 6 位码即可：${input.code}`,
    '',
    '如果这不是你本人的操作，忽略这封邮件即可，没有人能用它登录。',
    '',
    `Sign in to ${input.appName}: open the link above, or enter code ${input.code} on the login page. Valid for ${input.ttlMinutes} minutes.`,
  ].join('\n');

  const html = `<!doctype html>
<html lang="zh-CN">
<body style="margin:0;padding:24px;background:#f6f6f4;font-family:-apple-system,BlinkMacSystemFont,'PingFang SC','Microsoft YaHei',sans-serif;color:#1a1a1a;">
  <div style="max-width:480px;margin:0 auto;background:#fff;border-radius:12px;padding:32px;">
    <h1 style="font-size:20px;margin:0 0 16px;">登录 ${app}</h1>
    <p style="font-size:16px;line-height:1.6;margin:0 0 24px;">点击下面的按钮登录。链接 ${input.ttlMinutes} 分钟内有效，只能用一次。</p>
    <p style="margin:0 0 24px;"><a href="${link}" style="display:inline-block;background:#1a1a1a;color:#fff;text-decoration:none;padding:12px 24px;border-radius:8px;font-size:16px;">登录 ${app}</a></p>
    <p style="font-size:14px;line-height:1.6;color:#555;margin:0 0 8px;">在微信里打开的？回到登录页，输入这个 6 位码即可：</p>
    <p style="font-size:28px;letter-spacing:6px;font-weight:600;margin:0 0 24px;">${code}</p>
    <p style="font-size:13px;line-height:1.6;color:#777;margin:0 0 8px;">按钮打不开时，复制这个链接到浏览器：<br><span style="word-break:break-all;">${link}</span></p>
    <p style="font-size:13px;line-height:1.6;color:#777;margin:16px 0 0;">如果这不是你本人的操作，忽略这封邮件即可，没有人能用它登录。</p>
    <hr style="border:none;border-top:1px solid #eee;margin:24px 0;">
    <p style="font-size:12px;line-height:1.6;color:#999;margin:0;">Sign in to ${app}: open the link above, or enter code <strong>${code}</strong> on the login page. Valid for ${input.ttlMinutes} minutes.</p>
  </div>
</body>
</html>`;

  return { to: input.to, from: input.from, subject, html, text };
}
