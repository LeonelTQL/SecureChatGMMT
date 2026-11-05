import 'reflect-metadata';
import { PrismaClient } from '@prisma/client';
import * as argon2 from 'argon2';
import { readFileSync } from 'node:fs';
async function seed() {
  const db = new PrismaClient();
  try {
    const config = JSON.parse(readFileSync(process.env.BOOTSTRAP_CONFIG_PATH ?? '/run/keys/bootstrap.json', 'utf8'));
    const email = typeof config.email === 'string' ? config.email.trim().toLowerCase() : '';
    const password = typeof config.password === 'string' ? config.password : '';
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !password || password.length < 16 || password.length > 128 || !/\S/.test(password)) throw new Error('Configura ADMIN_EMAIL y ADMIN_PASSWORD (16–128 caracteres)');
    await db.$transaction(async tx => {
      const existing = await tx.user.findUnique({ where: { email } });
      if (existing) return;
      await tx.user.create({ data: { username: 'bootstrap_admin', email, passwordHash: await argon2.hash(password, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 }) } });
    }, { timeout: 15000 });
    console.log('Usuario inicial preparado sin asignar roles; no se imprimen credenciales');
  } finally { await db.$disconnect(); }
}
seed().catch(() => { console.error('No se pudo preparar el administrador. Revisa configuración, duplicados y conexión'); process.exitCode = 1; });
