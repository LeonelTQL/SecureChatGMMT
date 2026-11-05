import { UnauthorizedException } from '@nestjs/common';
export function bearer(value?: string): string {
  const match = /^Bearer ([^\s]{1,4096})$/i.exec(value ?? '');
  if (!match) throw new UnauthorizedException('Se requiere un token Bearer');
  return match[1];
}
