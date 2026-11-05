import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey } from 'node:crypto';
export function jwtOptions() {
  const privateKey = readFileSync(process.env.JWT_PRIVATE_KEY_PATH ?? '/run/keys/jwt-private.pem', 'utf8');
  const publicKey = readFileSync(process.env.JWT_PUBLIC_KEY_PATH ?? '/run/public/jwt-public.pem', 'utf8');
  const key = createPrivateKey(privateKey);
  if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new Error('Se requiere RSA de al menos 2048 bits');
  if (createPublicKey(key).export({ type: 'spki', format: 'pem' }) !== createPublicKey(publicKey).export({ type: 'spki', format: 'pem' })) throw new Error('Par de claves JWT inconsistente');
  if ((process.env.STEGO_SERVICE_TOKEN?.length ?? 0) < 32) throw new Error('Configura STEGO_SERVICE_TOKEN aleatorio de al menos 32 caracteres');
  return { privateKey, publicKey, signOptions: { algorithm: 'RS256' as const, expiresIn: 900, issuer: 'ms-users-auth', audience: 'chat-seguro' } };
}
