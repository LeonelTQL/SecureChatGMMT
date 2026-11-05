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
      Token: object({ access_token: text, token_type: { type: 'string', enum: ['Bearer'] }, expires_in: { type: 'integer', enum: [900] } }),
      Profile: object({ id: uuid, username, email,  }),
      Identity: object({ sub: uuid, username, email, jti: uuid, exp: { type: 'integer' },  }),
    },
  },
  paths: {
    '/health': { get: operation('Disponibilidad de AUTH y PostgreSQL', { public: true }) },
    '/api/auth/register': { post: operation('Registro público sin privilegios', { public: true, body: 'Register', status: 201, result: ref('User') }) },
    '/api/auth/login': { post: operation('Credenciales; máximo 10 intentos/correo y 30/IP por minuto', { public: true, body: 'Login', result: ref('Token') }) },
    '/api/auth/profile': { get: operation('Perfil de la sesión y roles actuales', { result: ref('Profile') }) },
    '/api/auth/logout': { post: operation('Revocar la sesión actual inmediatamente', { status: 204 }) },
    '/api/auth/verify': { post: operation('Verificar JWT, sesión, usuario y roles vigentes', { result: ref('Identity') }) },
    '/api/users': { post: operation('Bloqueado hasta integrar autorizaci?n: crear usuario sin roles', { body: 'Register', status: 201, result: ref('User') }), get: operation('Bloqueado hasta integrar autorizaci?n: listar hasta 100 usuarios', { result: array('User'), list: true }) },
    '/api/users/{id}': { patch: operation('Bloqueado hasta integrar autorizaci?n: actualizar o deshabilitar usuario; deshabilitar revoca sus sesiones', { body: 'UserPatch', id: true, result: ref('User') }) },
  },
};

for (const [path, methods] of Object.entries(authOpenApi.paths)) {
  if (path.startsWith('/api/users')) for (const endpoint of Object.values(methods as Record<string, any>)) {
    endpoint.responses = { 401: { description: 'Autenticaci?n requerida' }, 503: { description: 'Autorizaci?n de Alejandro pendiente; operaci?n bloqueada' } };
  }
}
