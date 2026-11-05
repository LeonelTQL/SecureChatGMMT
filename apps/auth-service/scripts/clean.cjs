const fs = require('node:fs');
const path = require('node:path');
const workspace = path.resolve(__dirname, '..');
const target = path.resolve(workspace, 'dist');
if (path.dirname(target) !== workspace || path.basename(target) !== 'dist') throw new Error('Ruta de compilación inválida');
fs.rmSync(target, { recursive: true, force: true });
