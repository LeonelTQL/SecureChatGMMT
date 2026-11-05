import { Controller, Get, Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaService } from './prisma.service';
import { RbacModule } from './rbac/rbac.module';
@Controller()
class HealthController {
  @Get('health')
  status() { return { service: 'ms-users-auth', status: 'ok' }; }
}
@Module({
  imports: [JwtModule.registerAsync({
    useFactory: () => {
      const secret = process.env.JWT_SECRET;
      if (!secret || Buffer.byteLength(secret) < 32) throw new Error('JWT_SECRET debe tener al menos 32 bytes');
      return { secret, signOptions: { algorithm: 'HS256' as const, expiresIn: 900, issuer: 'ms-users-auth', audience: 'chat-seguro' } };
    }
  }), RbacModule],
  controllers: [HealthController, AuthController], providers: [PrismaService, AuthService], exports: [AuthService],
})
export class AppModule { }