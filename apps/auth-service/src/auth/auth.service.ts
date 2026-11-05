import { Injectable, OnModuleInit, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';
import { randomBytes } from 'node:crypto';
import { PrismaService } from '../database/prisma.service';
import { LoginDto } from './dto/login.dto/login.dto';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { UsersService } from '../users/users.service';
import { hashPassword } from '../common/security/password';
import { AuthenticatedUser } from './interfaces/authenticated-user/authenticated-user.interface';
@Injectable()
export class AuthService implements OnModuleInit {
  private dummyHash!: string;
  constructor(private readonly users: UsersService, private readonly prisma: PrismaService, private readonly jwt: JwtService) {}
  async onModuleInit() { this.dummyHash = await hashPassword(randomBytes(32).toString('hex')); }
  register(dto: CreateUserDto) { return this.users.create(dto); }
  async login(dto: LoginDto) {
    const user = await this.users.findForAuthentication(dto.email);
    const valid = await argon2.verify(user?.passwordHash ?? this.dummyHash, dto.password);
    if (!user || !valid || !user.status) {
      console.log(JSON.stringify({ event: 'login.denied', timestamp: new Date().toISOString() }));
      throw new UnauthorizedException('Credenciales incorrectas');
    }
    const session = await this.prisma.session.create({ data: { userId: user.id, expiresAt: new Date(Date.now() + 900000) } });
    const access_token = await this.jwt.signAsync({ sub: user.id, email: user.email, jti: session.id });
    console.log(JSON.stringify({ event: 'login.allowed', user_id: user.id, timestamp: new Date().toISOString() }));
    return { access_token, token_type: 'Bearer', expires_in: 900 };
  }
  async verify(token: string): Promise<AuthenticatedUser> {
    let p: Record<string, any>;
    try {
      p = await this.jwt.verifyAsync(token, { algorithms: ['RS256'], issuer: 'ms-users-auth', audience: 'chat-seguro' });
      const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      if (typeof p.sub !== 'string' || !uuid.test(p.sub) || typeof p.jti !== 'string' || !uuid.test(p.jti) ||
          typeof p.exp !== 'number' || typeof p.iat !== 'number' || p.exp - p.iat > 900 || typeof p.email !== 'string') throw new Error('Invalid claims');
    } catch { throw new UnauthorizedException('Token inválido o expirado'); }
    const session = await this.prisma.session.findUnique({ where: { id: p.jti }, include: { user: { include: { userRoles: { include: { role: true } } } } } });
    if (!session || session.revoked || session.expiresAt <= new Date() || session.userId !== p.sub || !session.user.status) throw new UnauthorizedException('Sesión no vigente');
    return { sub: session.user.id, email: session.user.email, username: session.user.username, jti: session.id,
      exp: p.exp as number, roles: session.user.userRoles.filter(a => a.role.status).map(a => a.role.name) };
  }
  async logout(jti: string) { await this.prisma.session.update({ where: { id: jti }, data: { revoked: true } }); }
}
