require('reflect-metadata');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { JwtService } = require('@nestjs/jwt');
const { Prisma } = require('@prisma/client');
const argon2 = require('argon2');
const { AuthService } = require('../dist/auth.service');
const { AuthController } = require('../dist/auth.controller');
const { CredentialsDto } = require('../dist/auth.dto');
const { plainToInstance } = require('class-transformer');
const { validate } = require('class-validator');
const secret = 'test-secret-only-012345678901234567890';
const jwt = new JwtService({ secret, signOptions: { algorithm: 'HS256', issuer: 'ms-users-auth', audience: 'chat-seguro', expiresIn: 900 } });
const credentials = { email: 'leonel@example.com', password: 'ClaveDePrueba123!' };
async function fixture() {
  let stored;
  const prisma = { user: {
    create: async ({ data }) => {
      if (stored) throw new Prisma.PrismaClientKnownRequestError('duplicate', { code: 'P2002', clientVersion: '6.19.0' });
      stored = { id: 'd128b947-a340-4bb5-bd31-623a96604d17', ...data, createdAt: new Date() };
      return { id: stored.id, email: stored.email, createdAt: stored.createdAt };
    },
    findUnique: async ({ where }) => stored?.email === where.email ? stored : null,
  } };
  const auth = new AuthService(prisma, jwt);
  await auth.onModuleInit();
  return { auth, stored: () => stored };
}
test('registro almacena Argon2id y no devuelve el hash', async () => {
  const f = await fixture();
  const result = await f.auth.register(credentials);
  assert.equal(result.email, credentials.email);
  assert.equal(result.passwordHash, undefined);
  assert.match(f.stored().passwordHash, /^\$argon2id\$/);
  assert.ok(await argon2.verify(f.stored().passwordHash, credentials.password));
});
test('correo duplicado devuelve 409', async () => {
  const { auth } = await fixture();
  await auth.register(credentials);
  await assert.rejects(auth.register(credentials), e => e.getStatus() === 409);
});
test('login emite JWT verificable con expiración de 15 minutos', async () => {
  const { auth } = await fixture();
  await auth.register(credentials);
  const result = await auth.login(credentials);
  const claims = await auth.verify(result.access_token);
  assert.equal(claims.email, credentials.email);
  const decoded = jwt.decode(result.access_token);
  assert.equal(decoded.exp - decoded.iat, 900);
  assert.equal(decoded.passwordHash, undefined);
});
test('contraseña incorrecta y usuario inexistente devuelven el mismo 401', async () => {
  const { auth } = await fixture();
  await auth.register(credentials);
  for (const dto of [{ ...credentials, password: 'incorrecta12345' }, { ...credentials, email: 'missing@example.com' }]) {
    await assert.rejects(auth.login(dto), e => e.getStatus() === 401 && e.message === 'Credenciales incorrectas');
  }
});
test('rechaza token alterado, expirado, otra firma, audiencia o emisor', async () => {
  const { auth } = await fixture();
  const payload = { sub: '123', email: credentials.email };
  const tokens = ['invalid',
    jwt.sign(payload, { expiresIn: -1 }),
    jwt.sign(payload, { secret: 'another-secret' }),
    jwt.sign(payload, { audience: 'other' }),
    jwt.sign(payload, { issuer: 'other' }),
  ];
  for (const token of tokens) await assert.rejects(auth.verify(token), e => e.getStatus() === 401);
});
test('verify exige encabezado Bearer', async () => {
  const { auth } = await fixture();
  const controller = new AuthController(auth);
  for (const header of [undefined, '', 'Basic abc', 'Bearer']) assert.throws(() => controller.verify(header), e => e.getStatus() === 401);
});
test('DTO normaliza email y rechaza datos inválidos o campos extra', async () => {
  const dto = plainToInstance(CredentialsDto, { ...credentials, email: ' LEONEL@example.com ' });
  assert.equal(dto.email, 'leonel@example.com');
  assert.equal((await validate(dto)).length, 0);
  for (const data of [{ email: 'invalid', password: 'short' }, { ...credentials, role: 'ADMIN' }, { ...credentials, password: 123 }]) {
    assert.ok((await validate(plainToInstance(CredentialsDto, data), { whitelist: true, forbidNonWhitelisted: true })).length > 0);
  }
});
test('HTTP: registro, login, verify y casos negativos con ValidationPipe', async () => {
  const { Module, ValidationPipe } = require('@nestjs/common');
  const { NestFactory } = require('@nestjs/core');
  const request = require('supertest');
  const { auth } = await fixture();
  class TestModule {}
  Module({ controllers: [AuthController], providers: [{ provide: AuthService, useValue: auth }] })(TestModule);
  const app = await NestFactory.create(TestModule, { logger: false });
  app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true, forbidNonWhitelisted: true }));
  await app.init();
  try {
    const server = app.getHttpServer();
    await request(server).post('/auth/register').send({ ...credentials, role: 'ADMIN' }).expect(400);
    const registered = await request(server).post('/auth/register').send({ ...credentials, email: ' LEONEL@example.com ' }).expect(201);
    assert.equal(registered.body.email, credentials.email);
    assert.equal(registered.body.passwordHash, undefined);
    await request(server).post('/auth/register').send(credentials).expect(409);
    const login = await request(server).post('/auth/login').send(credentials).expect(200);
    const verified = await request(server).post('/auth/verify').set('Authorization', `Bearer ${login.body.access_token}`).expect(200);
    assert.equal(verified.body.sub, registered.body.id);
    await request(server).post('/auth/verify').expect(401);
    await request(server).post('/auth/login').send({ ...credentials, password: 'Incorrecta12345!' }).expect(401);
  } finally { await app.close(); }
});
