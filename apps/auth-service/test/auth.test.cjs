require('reflect-metadata');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync, randomUUID } = require('node:crypto');
const { JwtService } = require('@nestjs/jwt');
const { Prisma } = require('@prisma/client');
const { Module, ValidationPipe } = require('@nestjs/common');
const { APP_GUARD, NestFactory } = require('@nestjs/core');
const request = require('supertest');
const argon2 = require('argon2');
const { AuthService } = require('../dist/auth/auth.service');
const { AuthController } = require('../dist/auth/auth.controller');
const { UsersService } = require('../dist/users/users.service');
const { JwtAuthGuard } = require('../dist/auth/guards/jwt-auth/jwt-auth.guard');
const { RolesGuard } = require('../dist/auth/guards/roles/roles.guard');
const { LoginRateGuard } = require('../dist/common/guards/login-rate/login-rate.guard');
const { AuthorizationController } = require('../dist/authorization/authorization.controller');
const { AuthorizationService } = require('../dist/authorization/authorization.service');
const { AdminController } = require('../dist/admin/admin.controller');
const { SafeErrors } = require('../dist/common/filters/all-exceptions/all-exceptions.filter');
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privateKey = keys.privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' });
const jwt = new JwtService({ privateKey, publicKey, signOptions: { algorithm: 'RS256', issuer: 'ms-users-auth', audience: 'chat-seguro', expiresIn: 900 } });
const credentials = { username: 'leonel', email: 'leonel@example.com', password: 'ClaveDePrueba123!' };
const loginDto = { email: credentials.email, password: credentials.password };
async function fixture() {
  let user; const sessions = new Map();
  const db = { user: {
    create: async ({ data }) => {
      if (user) throw new Prisma.PrismaClientKnownRequestError('duplicate', { code: 'P2002', clientVersion: '6.19.0' });
      user = { id: randomUUID(), ...data, status: true, createdAt: new Date(), updatedAt: new Date(), userRoles: [] };
      const { passwordHash, userRoles, ...safe } = user; return safe;
    },
    findUnique: async ({ where }) => user?.email === where.email ? user : null,
  }, session: {
    create: async ({ data }) => { const session = { id: randomUUID(), ...data, revoked: false }; sessions.set(session.id, session); return session; },
    findUnique: async ({ where }) => { const s = sessions.get(where.id); return s ? { ...s, user } : null; },
    update: async ({ where, data }) => Object.assign(sessions.get(where.id), data),
  } };
  const auth = new AuthService(new UsersService(db), db, jwt); await auth.onModuleInit();
  return { auth, get user() { return user; }, sessions };
}
test('registro: hash Argon2id, sin secretos, duplicado 409', async () => {
  const f = await fixture(); const result = await f.auth.register(credentials);
  assert.equal(result.passwordHash, undefined);
  assert.match(f.user.passwordHash, /^\$argon2id\$/);
  assert.ok(await argon2.verify(f.user.passwordHash, credentials.password));
  await assert.rejects(f.auth.register(credentials), e => e.getStatus() === 409);
});
test('login RS256: firma, claims, duración, sesión y ausencia de roles en token', async () => {
  const f = await fixture(); await f.auth.register(credentials);
  const result = await f.auth.login(loginDto); const p = jwt.decode(result.access_token);
  await assert.rejects(f.auth.verify(result.access_token + 'x'), e => e.getStatus() === 401);
  assert.equal(p.exp - p.iat, 900); assert.equal(p.roles, undefined); assert.equal(p.passwordHash, undefined);
  assert.equal((await f.auth.verify(result.access_token)).sub, f.user.id);
});
test('credenciales incorrectas, usuario inexistente y cuenta deshabilitada: 401 genérico', async () => {
  const f = await fixture(); await f.auth.register(credentials);
  for (const dto of [{ ...loginDto, password: 'Incorrecta12345!' }, { ...loginDto, email: 'missing@example.com' }]) {
    await assert.rejects(f.auth.login(dto), e => e.getStatus() === 401 && e.message === 'Credenciales incorrectas');
  }
  f.user.status = false;
  await assert.rejects(f.auth.login(loginDto), e => e.getStatus() === 401);
});
test('JWT inválido, expirado, audiencia/emisor/firma incorrectos y claims ausentes: 401', async () => {
  const f = await fixture(); const p = { sub: randomUUID(), email: credentials.email, jti: randomUUID() };
  const otherKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  for (const token of ['invalid', jwt.sign(p, { expiresIn: -1 }), jwt.sign(p, { audience: 'other' }), jwt.sign(p, { issuer: 'other' }),
    jwt.sign(p, { privateKey: otherKey }), jwt.sign({ sub: p.sub }), jwt.sign(p, { expiresIn: 901 })]) {
    await assert.rejects(f.auth.verify(token), e => e.getStatus() === 401);
  }
});
test('revocación de rol inmediata con el mismo JWT y roles desactivados', async () => {
  const f = await fixture(); await f.auth.register(credentials);
  f.user.userRoles = [{ role: { name: 'ANALYST', status: true } }];
  const { access_token } = await f.auth.login(loginDto);
  assert.deepEqual((await f.auth.verify(access_token)).roles, ['ANALYST']);
  f.user.userRoles[0].role.status = false;
  assert.deepEqual((await f.auth.verify(access_token)).roles, []);
  f.user.userRoles = [];
  assert.deepEqual((await f.auth.verify(access_token)).roles, []);
});
test('logout revoca JWT y usuario inactivo rechaza sesión', async () => {
  const f = await fixture(); await f.auth.register(credentials);
  const { access_token } = await f.auth.login(loginDto);
  const identity = await f.auth.verify(access_token);
  f.user.status = false; await assert.rejects(f.auth.verify(access_token), e => e.getStatus() === 401);
  f.user.status = true; await f.auth.logout(identity.jti);
  await assert.rejects(f.auth.verify(access_token), e => e.getStatus() === 401);
});
async function httpFixture() {
  const f = await fixture();
  class TestModule {}
  Module({ controllers: [AuthController, AuthorizationController, AdminController], providers: [
    { provide: AuthService, useValue: f.auth }, AuthorizationService,
    { provide: APP_GUARD, useClass: LoginRateGuard },
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
  ] })(TestModule);
  const app = await NestFactory.create(TestModule, { logger: false });
  app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true, forbidNonWhitelisted: true }));
  app.useGlobalFilters(new SafeErrors()); await app.init();
  return { app, f, client: request(app.getHttpServer()) };
}
test('HTTP: validación, normalización, perfil y logout', async () => {
  const { app, f, client } = await httpFixture();
  try {
    for (const dto of [{ ...credentials, role: 'ADMIN' }, { ...credentials, password: ' '.repeat(12) }, { ...credentials, username: undefined }])
      await client.post('/auth/register').send(dto).expect(400);
    const registered = await client.post('/auth/register').send({ ...credentials, email: ' LEONEL@example.com ' }).expect(201);
    assert.equal(registered.body.email, credentials.email); assert.equal(registered.body.passwordHash, undefined);
    const login = await client.post('/auth/login').send(loginDto).expect(200);
    const token = login.body.access_token;
    await client.get('/auth/profile').expect(401);
    await client.get('/auth/profile').set('Authorization', `Bearer ${token}`).expect(200);
    await client.get('/admin/protected').set('Authorization', `Bearer ${token}`).expect(403);
    f.user.userRoles = [{ role: { name: 'ADMIN', status: true } }];
    await client.get('/admin/protected').set('Authorization', `Bearer ${token}`).expect(200);
    await client.post('/auth/logout').set('Authorization', `Bearer ${token}`).expect(204);
    await client.post('/auth/verify').set('Authorization', `Bearer ${token}`).expect(401);
  } finally { await app.close(); }
});
test('endpoint interno: exige identidad de STEGO y decide sobre roles actuales', async () => {
  process.env.STEGO_SERVICE_TOKEN = 'test-service-token-only-01234567890123456789';
  const { app, f, client } = await httpFixture();
  try {
    await f.auth.register(credentials);
    const { access_token } = await f.auth.login(loginDto);
    const body = { subject_token: access_token, action: 'steganography.analyze', resource_id: null };
    await client.post('/internal/authorization/check').send(body).expect(401);
    await client.post('/internal/authorization/check').set('X-Service-Token', 'wrong').send(body).expect(401);
    const check = () => client.post('/internal/authorization/check').set('X-Service-Token', process.env.STEGO_SERVICE_TOKEN).send(body).expect(200);
    assert.equal((await check()).body.allowed, false);
    f.user.userRoles = [{ role: { name: 'ANALYST', status: true } }];
    assert.equal((await check()).body.allowed, true);
    f.user.userRoles = [];
    assert.equal((await check()).body.allowed, false);
  } finally { await app.close(); delete process.env.STEGO_SERVICE_TOKEN; }
});
test('login tiene límite de intentos y no confía en X-Forwarded-For del cliente', async () => {
  const { app, client } = await httpFixture();
  try {
    // DTO inválido evita coste Argon2: aun así consume el presupuesto de intentos.
    for (let i = 0; i < 10; i++) await client.post('/auth/login').set('X-Forwarded-For', `1.1.1.${i}`).send({ email: credentials.email }).expect(400);
    await client.post('/auth/login').send({ email: credentials.email }).expect(429);
  } finally { await app.close(); }
});
