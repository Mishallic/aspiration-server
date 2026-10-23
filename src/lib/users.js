// The only shape in which a user leaves the server. Never return a model directly.
export function toPublicUser(user) {
  return {
    id: user.id,
    email: user.email,
    emailVerified: Boolean(user.emailVerifiedAt),
    firstName: user.firstName ?? null,
    lastName: user.lastName ?? null,
    avatarUrl: user.avatarUrl ?? null,
    role: user.role,
    hasPassword: Boolean(user.passwordHash),
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

export const normalizeEmail = (email) => email.trim().toLowerCase();
