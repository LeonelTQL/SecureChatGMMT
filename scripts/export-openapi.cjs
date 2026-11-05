const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');
const { authOpenApi } = require(path.join(root, 'apps/auth-service/dist/config/openapi.js'));
fs.mkdirSync(path.join(root, 'docs'), { recursive: true });
fs.writeFileSync(path.join(root, 'docs/auth.openapi.json'), JSON.stringify(authOpenApi, null, 2) + '\n');
