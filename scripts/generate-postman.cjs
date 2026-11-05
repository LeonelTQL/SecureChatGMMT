const fs = require('node:fs');
const path = require('node:path');
const items = [];
function add(name, method, url, body, token = true, save, status = 200) {
  const request = { method, url, header: [] };
  if (token) request.header.push({ key: 'Authorization', value: 'Bearer {{access_token}}' });
  if (body) { request.header.push({ key: 'Content-Type', value: 'application/json' }); request.body = { mode: 'raw', raw: JSON.stringify(body, null, 2) }; }
  const exec = [`pm.test('HTTP ${status}', () => pm.response.to.have.status(${status}));`];
  if (save) exec.push(`if (pm.response.code === ${status}) pm.collectionVariables.set('access_token', pm.response.json().access_token);`);
  items.push({ name, request, event: [{ listen: 'test', script: { type: 'text/javascript', exec } }] });
}
const credentials = { email: '{{email}}', password: '{{password}}' };
add('01 Registro', 'POST', '{{auth_url}}/api/auth/register', { ...credentials, username: '{{username}}' }, false, false, 201);
add('02 Login', 'POST', '{{auth_url}}/api/auth/login', credentials, false, true);
add('03 Perfil', 'GET', '{{auth_url}}/api/auth/profile');
add('04 Verificar JWT', 'POST', '{{auth_url}}/api/auth/verify');
add('05 Usuario sin ADMIN: administracion denegada', 'GET', '{{auth_url}}/api/users', null, true, false, 403);
add('06 Usuario sin ANALYST: analisis denegado', 'POST', '{{stego_url}}/api/steganography/analyze', null, true, false, 403);
add('07 Logout', 'POST', '{{auth_url}}/api/auth/logout', null, true, false, 204);
add('08 JWT revocado', 'GET', '{{auth_url}}/api/auth/profile', null, true, false, 401);
add('09 Sin autenticación', 'POST', '{{stego_url}}/api/steganography/analyze', null, false, false, 401);
const variables = { auth_url: 'https://localhost:3001', stego_url: 'https://localhost:8000', username: 'postman_user', email: 'postman@example.com', password: '', access_token: '' };
const collection = { info: { name: 'Backend V1 - autenticacion, RBAC y STEGO', schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json', description: 'Importar CA secrets/public/ca.pem. Configurar password local de 12-128 caracteres. RBAC activo: las cuentas nuevas no tienen roles y reciben 403 en administracion y analisis. STEGO activo integra el pipeline de Diana; esta secuencia comprueba denegacion sin roles, no un analisis autorizado.' }, variable: Object.entries(variables).map(([key, value]) => ({ key, value })), item: items };
fs.writeFileSync(path.join(__dirname, '../postman/Backend-V1.postman_collection.json'), JSON.stringify(collection, null, 2) + '\n');
