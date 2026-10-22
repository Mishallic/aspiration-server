import nodemailer from 'nodemailer';

// Sends email over SMTP_URL. Without it, development and test print emails to the
// console so links can be clicked locally; production skips sending and warns,
// because printing reset links into production logs would leak them.
export function createMailer({ config, logger = console }) {
  const { smtpUrl, from } = config.email;
  const transport = smtpUrl ? nodemailer.createTransport(smtpUrl) : null;
  const outbox = [];
  let warned = false;

  async function send({ to, subject, text, html }) {
    const message = { from, to, subject, text, html };
    if (config.env === 'test') {
      outbox.push(message);
      return;
    }
    if (transport) {
      await transport.sendMail(message);
      return;
    }
    if (config.isProduction) {
      if (!warned) {
        logger.warn('SMTP_URL is not set: verification and password reset emails are not being sent.');
        warned = true;
      }
      return;
    }
    logger.info(`\n--- email to ${to} ---\nSubject: ${subject}\n\n${text}\n--- end email ---\n`);
  }

  // Email failures must not break the request that triggered them, or leak whether
  // an address exists. They are logged instead.
  function sendInBackground(message) {
    send(message).catch((err) => logger.error(`Failed to send email to ${message.to}: ${err.message}`));
  }

  return { send, sendInBackground, outbox, configured: Boolean(transport) };
}
