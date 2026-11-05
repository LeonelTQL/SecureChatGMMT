import { ConflictException, Injectable, OnModuleInit, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Prisma } from '@prisma/client';
import * as argon2 from 'argon2';
import { randomBytes } from 'node:crypto';
import { PrismaService } from './prisma.service';
import { CredentialsDto } from './auth.dto';
@Injectable()
export class AuthService implements OnModuleInit {
  private dummyHash!: string;
  constructor(private readonly prisma: PrismaService, private readonly jwt: JwtService) {}
  async onModuleInit() { this.dummyHash = await this.hash(randomBytes(32).toString('hex')); }
  private hash(password: string) {
    return argon2.hash(password, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
  }
  async register(dto: CredentialsDto) {
    const passwordHash = await this.hash(dto.password);
    try {
      return await this.prisma.user.create({ data: { email: dto.email, passwordHash }, select: { id: true, email: true, createdAt: true } });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') throw new ConflictException('El correo ya está registrado');
      throw error;
    }
  }
  async login(dto: CredentialsDto) {
    const user = await this.prisma.user.findUnique({ where: { email: dto.email } });
    const valid = await argon2.verify(user?.passwordHash ?? this.dummyHash, dto.password);
    if (!user || !valid) throw new UnauthorizedException('Credenciales incorrectas');
    return { access_token: await this.jwt.signAsync({ sub: user.id, email: user.email }), token_type: 'Bearer', expires_in: 900 };
  }
  async verify(token: string) {
    try {
      const p = await this.jwt.verifyAsync(token, { algorithms: ['HS256'], issuer: 'ms-users-auth', audience: 'chat-seguro' });
      if (typeof p.sub !== 'string' || typeof p.exp !== 'number' || typeof p.email !== 'string') throw new Error('Invalid claims');
      return { sub: p.sub as string, email: p.email as string, exp: p.exp as number };
    } catch { throw new UnauthorizedException('Token inválido o expirado'); }
  }
}
