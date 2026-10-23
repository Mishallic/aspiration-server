import { conflict } from '../lib/errors.js';
import { toPublicUser, normalizeEmail } from '../lib/users.js';

// Turns a verified provider profile into a local user, shared by every OAuth path
// (native ID token and web redirect) so linking rules stay in one place.
//
// Linking by email is only safe when the provider has verified that email. Otherwise
// an attacker could register a provider account with someone else's unverified address
// and take over their account. Callers must pass emailVerified truthfully.
export function createAccountService({ sequelize, models, services }) {
  const { User, Identity } = models;

  async function findOrCreateFromProvider(profile) {
    const { provider, providerUserId, emailVerified } = profile;
    const email = profile.email ? normalizeEmail(profile.email) : null;

    return sequelize.transaction(async (transaction) => {
      // 1. Known identity: this provider account has signed in before.
      const existing = await Identity.findOne({
        where: { provider, providerUserId },
        transaction,
      });
      if (existing) {
        const user = await User.findByPk(existing.userId, { transaction });
        return { user, created: false };
      }

      // 2. Link to an existing local account, but only on a provider-verified email
      // AND only when that account is itself trustworthy. Auto-merging a verified
      // provider identity into an account that has a password but was never
      // email-verified would let an attacker pre-register the victim's address with
      // a password, then inherit the account when the victim signs in with the
      // provider. Such an account must prove control (sign in with the password)
      // before a provider identity is attached.
      if (email && emailVerified) {
        const user = await User.findOne({ where: { email }, transaction });
        if (user) {
          if (user.passwordHash && !user.emailVerifiedAt) {
            throw conflict(
              'account_exists',
              'An account with this email already exists. Sign in with your password to link this provider.',
            );
          }
          await Identity.create(
            { userId: user.id, provider, providerUserId, email },
            { transaction },
          );
          if (!user.emailVerifiedAt) await user.update({ emailVerifiedAt: new Date() }, { transaction });
          return { user, created: false };
        }
      }

      // 3. Brand new user. No password: they sign in through the provider.
      // An unverified or colliding provider email must not occupy the canonical
      // email slot, so it is kept only on the identity and the user gets a
      // non-routable placeholder address instead.
      const emailTaken = email ? Boolean(await User.findOne({ where: { email }, transaction })) : false;
      const trustEmail = Boolean(email) && emailVerified && !emailTaken;
      const user = await User.create(
        {
          email: trustEmail ? email : `${provider}_${providerUserId}@users.noreply.local`,
          emailVerifiedAt: trustEmail ? new Date() : null,
          firstName: profile.firstName ?? null,
          lastName: profile.lastName ?? null,
          avatarUrl: profile.avatarUrl ?? null,
        },
        { transaction },
      );
      await Identity.create({ userId: user.id, provider, providerUserId, email }, { transaction });
      return { user, created: true };
    });
  }

  // Wraps the above and fires the webhook for genuinely new users.
  async function signInWithProvider(profile, meta) {
    const { user, created } = await findOrCreateFromProvider(profile);
    if (created) services.webhooks.emit('user.created', { user: toPublicUser(user), provider: profile.provider });
    const session = await services.sessions.createSession(user, meta);
    return { user, session, created };
  }

  return { findOrCreateFromProvider, signInWithProvider };
}
