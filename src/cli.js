import { loadConfig } from './config.js';
import { createContext } from './context.js';
import { normalizeEmail } from './lib/users.js';

const USAGE = `Usage: node src/cli.js <command>

Commands:
  migrate                 Apply database migrations (the server also does this on start)
  make-admin <email>      Give a user the admin role
  remove-admin <email>    Take the admin role away
  rotate-key              Create a new signing key; the old one stays published until the next rotation
`;

async function setRole(ctx, email, role) {
  if (!email) throw new Error('An email address is required');
  const user = await ctx.models.User.findOne({ where: { email: normalizeEmail(email) } });
  if (!user) throw new Error(`No user with email ${email}`);
  await user.update({ role });
  // Revoke sessions so the new role shows up in the next token instead of after expiry.
  await ctx.services.sessions.revokeAllSessions(user.id);
  return `${user.email} is now ${role}. Their sessions were signed out so the change applies at once.`;
}

async function run(command, arg) {
  try {
    process.loadEnvFile();
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
  const ctx = await createContext(loadConfig());
  try {
    switch (command) {
      case 'migrate':
        return 'Migrations are up to date.';
      case 'make-admin':
        return await setRole(ctx, arg, 'admin');
      case 'remove-admin':
        return await setRole(ctx, arg, 'user');
      case 'rotate-key': {
        const kid = await ctx.services.keys.rotate();
        return `New signing key ${kid} is active. Restart running servers so they sign with it.`;
      }
      default:
        return null;
    }
  } finally {
    await ctx.close();
  }
}

const [command, arg] = process.argv.slice(2);
run(command, arg)
  .then((message) => {
    if (message === null) {
      process.stdout.write(USAGE);
      process.exit(command ? 1 : 0);
    }
    console.log(message);
  })
  .catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
