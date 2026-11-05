require('reflect-metadata');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { JwtService } = require('@nestjs/jwt');
const { Reflector } = require('@nestjs/core');
const { Role } = require('../dist/rbac/enums/role.enum');
const { JwtAuthGuard } = require('../dist/rbac/guards/jwt-auth.guard');
const { RolesGuard } = require('../dist/rbac/guards/roles.guard');
const { AdminController } = require('../dist/rbac/controllers/admin.controller');

const secret = 'test-secret-only-012345678901234567890';
const jwt = new JwtService({
    secret,
    signOptions: {
        algorithm: 'HS256',
        issuer: 'ms-users-auth',
        audience: 'chat-seguro',
        expiresIn: 900,
    },
});

function createMockContext(headers = {}, user = undefined, handler = () => { }, cls = class { }) {
    const req = { headers, user };
    return {
        req,
        context: {
            switchToHttp: () => ({ getRequest: () => req }),
            getHandler: () => handler,
            getClass: () => cls,
        },
    };
}

test('JwtAuthGuard rechaza solicitud sin JWT o sin formato Bearer con 401', async () => {
    const guard = new JwtAuthGuard(jwt);
    for (const authorization of [undefined, '', 'Basic 123', 'Bearer', 'Bearer a b']) {
        const { context } = createMockContext(authorization ? { authorization } : {});
        await assert.rejects(
            () => guard.canActivate(context),
            (err) => err.getStatus() === 401,
        );
    }
});

test('JwtAuthGuard rechaza JWT inválido, expirado, con otra firma, emisor o audiencia con 401', async () => {
    const guard = new JwtAuthGuard(jwt);
    const validPayload = { sub: 'user-1', email: 'user@example.com', role: Role.USER };
    const invalidTokens = [
        'token.invalido.alterado',
        jwt.sign(validPayload, { expiresIn: -10 }),
        jwt.sign(validPayload, { secret: 'otra-clave-secreta-diferente-0123456789' }),
        jwt.sign(validPayload, { issuer: 'otro-emisor' }),
        jwt.sign(validPayload, { audience: 'otra-audiencia' }),
    ];

    for (const token of invalidTokens) {
        const { context } = createMockContext({ authorization: `Bearer ${token}` });
        await assert.rejects(
            () => guard.canActivate(context),
            (err) => err.getStatus() === 401,
        );
    }
});

test('JwtAuthGuard rechaza token con claims ausentes o malformados con 401', async () => {
    const guard = new JwtAuthGuard(jwt);
    const malformedPayloads = [
        { sub: 'user-1', email: 'user@example.com' }, // sin role
        { sub: 'user-1', email: 'user@example.com', role: 'SUPERADMIN' }, // role inválido
        { email: 'user@example.com', role: Role.ADMIN }, // sin sub
        { sub: 'user-1', role: Role.ADMIN }, // sin email
    ];

    for (const payload of malformedPayloads) {
        const token = jwt.sign(payload);
        const { context } = createMockContext({ authorization: `Bearer ${token}` });
        await assert.rejects(
            () => guard.canActivate(context),
            (err) => err.getStatus() === 401,
        );
    }
});

test('RolesGuard permite acceso a endpoints sin restricción de roles (@Roles)', () => {
    const reflector = new Reflector();
    const guard = new RolesGuard(reflector);
    const { context } = createMockContext({}, { sub: '1', email: 'a@b.com', role: Role.USER, exp: 999999 });
    assert.equal(guard.canActivate(context), true);
});

test('HTTP GET /admin/protected: 401 sin token/inválido, 403 con USER y 200 con ADMIN', async () => {
    const { Module } = require('@nestjs/common');
    const { NestFactory } = require('@nestjs/core');
    const request = require('supertest');

    class TestRbacModule { }
    Module({
        controllers: [AdminController],
        providers: [
            JwtAuthGuard,
            RolesGuard,
            { provide: JwtService, useValue: jwt },
        ],
    })(TestRbacModule);

    const app = await NestFactory.create(TestRbacModule, { logger: false });
    await app.init();

    try {
        const server = app.getHttpServer();

        // 1. Solicitud sin JWT -> 401
        await request(server).get('/admin/protected').expect(401);

        // 2. JWT inválido o vencido -> 401
        const expiredToken = jwt.sign(
            { sub: 'admin-1', email: 'admin@example.com', role: Role.ADMIN },
            { expiresIn: -5 },
        );
        await request(server)
            .get('/admin/protected')
            .set('Authorization', `Bearer ${expiredToken}`)
            .expect(401);

        // 3. JWT válido con rol USER en endpoint ADMIN -> 403
        const userToken = jwt.sign({
            sub: 'user-1',
            email: 'user@example.com',
            role: Role.USER,
        });
        await request(server)
            .get('/admin/protected')
            .set('Authorization', `Bearer ${userToken}`)
            .expect(403);

        // 4. JWT válido con rol ADMIN -> 200
        const adminToken = jwt.sign({
            sub: 'admin-1',
            email: 'admin@example.com',
            role: Role.ADMIN,
        });
        const res = await request(server)
            .get('/admin/protected')
            .set('Authorization', `Bearer ${adminToken}`)
            .expect(200);

        assert.equal(res.body.user.sub, 'admin-1');
        assert.equal(res.body.user.email, 'admin@example.com');
        assert.equal(res.body.user.role, Role.ADMIN);
    } finally {
        await app.close();
    }
});