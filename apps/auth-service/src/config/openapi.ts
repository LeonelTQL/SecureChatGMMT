const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
const object = (properties: Record<string, unknown>, required: string[] = []) => ({ type: 'object', additionalProperties: false, properties, required });
const text = { type: 'string' };
const uuid = { type: 'string', format: 'uuid' };
const email = { type: 'string', format: 'email', maxLength: 254 };
const password = { type: 'string', minLength: 12, maxLength: 128, writeOnly: true };
const username = { type: 'string', pattern: '^[a-z0-9._-]{3,50}$' };
const timestamp = { type: 'string', format: 'date-time' };
const operation = (summary: string, options: { body?: string; result?: unknown; status?: number; public?: boolean; service?: boolean; id?: boolean; list?: boolean } = {}) => ({
  summary,
  security: options.public ? [] : options.service ? [{ service: [] }] : [{ bearer: [] }],
  ...(options.body ? { requestBody: { required: true, content: { 'application/json': { schema: ref(options.body) } } } } : {}),
  ...(options.id ? { parameters: [{ name: 'id', in: 'path', required: true, schema: uuid }] } :
    options.list ? { parameters: [{ name: 'offset', in: 'query', schema: { type: 'integer', minimum: 0, maximum: 1000000 } }] } : {}),
  responses: {
    [options.status ?? 200]: { description: 'Operación completada', ...(options.result ? { content: { 'application/json': { schema: options.result } } } : {}) },
    400: { description: 'Datos inválidos' }, 401: { description: 'Autenticación inválida o sesión revocada' },
    403: { description: 'Rol vigente insuficiente' }, 404: { description: 'Recurso inexistente' },
    409: { description: 'Valor único o asignación duplicada' }, 429: { description: 'Límite de intentos' }, 500: { description: 'Error interno sin información sensible' },
  },
});
const array = (name: string) => ({ type: 'array', items: ref(name) });
export const authOpenApi: any = {
  openapi: '3.0.3', info: { title: 'AUTH Backend V1', version: '2.0.0', description: 'JWT RS256, sesiones revocables y autorización sobre asignaciones actuales. ADMIN administra identidad; USER consulta perfil; ANALYST analiza y consulta resultados propios.' },
  servers: [{ url: 'https://localhost:3001' }],
  components: {
    securitySchemes: { bearer: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }, service: { type: 'apiKey', in: 'header', name: 'X-Service-Token' } },
    schemas: {
      Login: object({ email, password }, ['email', 'password']),
      Register: object({ username, email, password }, ['username', 'email', 'password']),
      User: object({ id: uuid, username, email, status: { type: 'boolean' }, createdAt: timestamp, updatedAt: timestamp }),
      UserPatch: object({ username, email, status: { type: 'boolean' } }),
      RoleCreate: object({ name: { type: 'string', enum: ['ADMIN', 'ANALYST', 'USER'] }, description: { type: 'string', minLength: 1, maxLength: 250 } }, ['name', 'description']),
      Role: object({ id: uuid, name: text, description: text, status: { type: 'boolean' }, createdAt: timestamp, updatedAt: timestamp }),
      RolePatch: object({ description: { type: 'string', minLength: 1, maxLength: 250 }, status: { type: 'boolean' } }),
      AssignmentCreate: object({ user_id: uuid, role_id: uuid }, ['user_id', 'role_id']),
      Assignment: object({ id: uuid, userId: uuid, roleId: uuid, assignedAt: timestamp }),
      Token: object({ access_token: text, token_type: { type: 'string', enum: ['Bearer'] }, expires_in: { type: 'integer', enum: [900] } }),
      Profile: object({ id: uuid, username, email, roles: { type: 'array', items: text } }),
      Identity: object({ sub: uuid, username, email, jti: uuid, exp: { type: 'integer' }, roles: { type: 'array', items: text } }),
      Check: object({ subject_token: { type: 'string', maxLength: 4096 }, action: { type: 'string', enum: ['steganography.analyze', 'steganography.results.read'] }, resource_id: { ...uuid, nullable: true } }, ['subject_token', 'action']),
      Decision: object({ subject_id: uuid, action: text, resource_id: { ...uuid, nullable: true }, allowed: { type: 'boolean' }, reason: text, scope: { type: 'string', enum: ['own', 'all'] } }),
    },
  },
  paths: {
    '/health': { get: operation('Disponibilidad de AUTH y PostgreSQL', { public: true }) },
    '/api/auth/register': { post: operation('Registro público sin privilegios', { public: true, body: 'Register', status: 201, result: ref('User') }) },
    '/api/auth/login': { post: operation('Credenciales; máximo 10 intentos/correo y 30/IP por minuto', { public: true, body: 'Login', result: ref('Token') }) },
    '/api/auth/profile': { get: operation('Perfil de la sesión y roles actuales', { result: ref('Profile') }) },
    '/api/auth/logout': { post: operation('Revocar la sesión actual inmediatamente', { status: 204 }) },
    '/api/auth/verify': { post: operation('Verificar JWT, sesión, usuario y roles vigentes', { result: ref('Identity') }) },
    '/api/users': { post: operation('ADMIN: crear usuario sin roles', { body: 'Register', status: 201, result: ref('User') }), get: operation('ADMIN: listar hasta 100 usuarios', { result: array('User'), list: true }) },
    '/api/users/{id}': { patch: operation('ADMIN: actualizar o deshabilitar usuario; deshabilitar revoca sus sesiones', { body: 'UserPatch', id: true, result: ref('User') }) },
    '/api/roles': { post: operation('ADMIN: crear rol', { body: 'RoleCreate', status: 201, result: ref('Role') }), get: operation('ADMIN: listar roles', { result: array('Role') }) },
    '/api/roles/{id}': { patch: operation('ADMIN: actualizar descripción o estado', { body: 'RolePatch', id: true, result: ref('Role') }) },
    '/api/user-roles': { post: operation('ADMIN: asignar rol; relación N:M única', { body: 'AssignmentCreate', status: 201, result: ref('Assignment') }), get: operation('ADMIN: listar asignaciones', { result: array('Assignment'), list: true }) },
    '/api/user-roles/{id}': { delete: operation('ADMIN: retirar asignación; efecto en próximas operaciones', { id: true, status: 204 }) },
    '/api/admin/protected': { get: operation('ADMIN: demostración de RBAC') },
    '/internal/authorization/check': { post: operation('Solo STEGO: consultar autorización vigente; STEGO aplica propiedad usando su base', { service: true, body: 'Check', result: ref('Decision') }) },
  },
};
