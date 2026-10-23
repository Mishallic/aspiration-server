import { PURPOSES } from './oneTimeTokens.js';

export const VERIFY_EMAIL_TTL_SECONDS = 24 * 3600;
export const RESET_PASSWORD_TTL_SECONDS = 30 * 60;

const escapeHtml = (value) =>
  String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function withToken(base, token) {
  const url = new URL(base);
  url.searchParams.set('token', token);
  return url.toString();
}

function render({ appName, heading, intro, actionLabel, link, footer }) {
  const text = `${heading}\n\n${intro}\n\n${actionLabel}: ${link}\n\n${footer}\n`;
  const html = `<!doctype html><html><body style="font-family:system-ui,sans-serif;max-width:480px;margin:auto;padding:24px;color:#111">
<h2 style="margin:0 0 12px">${escapeHtml(heading)}</h2>
<p>${escapeHtml(intro)}</p>
<p><a href="${escapeHtml(link)}" style="display:inline-block;background:#111;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none">${escapeHtml(actionLabel)}</a></p>
<p style="font-size:13px;color:#555">${escapeHtml(footer)}</p>
<p style="font-size:12px;color:#888">${escapeHtml(appName)}</p>
</body></html>`;
  return { text, html };
}

// Issues the single-use links and composes the emails that carry them,
// and consumes those links when they come back.
export function createEmailFlows({ config, models, services }) {
  const { oneTimeTokens, mailer } = services;
  const { User } = models;
  const appName = config.appName;

  async function sendVerification(user) {
    await oneTimeTokens.revokeAll({ userId: user.id, purpose: PURPOSES.VERIFY_EMAIL });
    const token = await oneTimeTokens.issue({
      purpose: PURPOSES.VERIFY_EMAIL,
      userId: user.id,
      data: { email: user.email },
      ttlSeconds: VERIFY_EMAIL_TTL_SECONDS,
    });
    const link = withToken(`${config.publicUrl}/verify-email`, token);
    mailer.sendInBackground({
      to: user.email,
      subject: `Confirm your email for ${appName}`,
      ...render({
        appName,
        heading: 'Confirm your email',
        intro: `Confirm that ${user.email} is your email address.`,
        actionLabel: 'Confirm email',
        link,
        footer: 'This link expires in 24 hours. If you did not sign up, ignore this email.',
      }),
    });
    return token;
  }

  async function sendPasswordReset(user) {
    await oneTimeTokens.revokeAll({ userId: user.id, purpose: PURPOSES.RESET_PASSWORD });
    const token = await oneTimeTokens.issue({
      purpose: PURPOSES.RESET_PASSWORD,
      userId: user.id,
      data: { email: user.email },
      ttlSeconds: RESET_PASSWORD_TTL_SECONDS,
    });
    const link = withToken(config.email.passwordResetUrl ?? `${config.publicUrl}/reset-password`, token);
    mailer.sendInBackground({
      to: user.email,
      subject: `Reset your ${appName} password`,
      ...render({
        appName,
        heading: 'Reset your password',
        intro: 'Someone asked to reset the password for this account. If it was you, choose a new password.',
        actionLabel: 'Choose a new password',
        link,
        footer: 'This link expires in 30 minutes and works once. If you did not ask for it, ignore this email.',
      }),
    });
    return token;
  }

  // Consumes a verification link. A token is single-use, so a bad or reused one
  // returns null. The email is pinned in the token, so a token stays valid for the
  // address it was issued for even if the user later changes their email.
  async function verifyEmail(rawToken) {
    const record = await oneTimeTokens.consume({ purpose: PURPOSES.VERIFY_EMAIL, raw: rawToken });
    if (!record?.userId) return null;
    const user = await User.findByPk(record.userId);
    if (!user) return null;
    if (!user.emailVerifiedAt) await user.update({ emailVerifiedAt: new Date() });
    return user;
  }

  // Consumes a reset link and returns the user. The caller sets the new password,
  // so the token is spent exactly once whether or not the new password is valid...
  // which is why the route validates the new password BEFORE calling this.
  async function consumePasswordReset(rawToken) {
    const record = await oneTimeTokens.consume({ purpose: PURPOSES.RESET_PASSWORD, raw: rawToken });
    if (!record?.userId) return null;
    return User.findByPk(record.userId);
  }

  return { sendVerification, sendPasswordReset, verifyEmail, consumePasswordReset };
}
