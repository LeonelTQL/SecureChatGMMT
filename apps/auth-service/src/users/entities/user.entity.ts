import type { Prisma, User as PersistedUser } from '@prisma/client';
// Prisma define la entidad persistida en schema.prisma; la entidad pública excluye credenciales.
export type User = Omit<PersistedUser, 'passwordHash'>;
export const userFields = {
  id: true, username: true, email: true, status: true, createdAt: true, updatedAt: true,
} as const satisfies Prisma.UserSelect;
