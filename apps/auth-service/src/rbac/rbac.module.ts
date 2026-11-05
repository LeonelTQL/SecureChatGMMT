import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AdminController } from './controllers/admin.controller';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';

@Module({
    imports: [
        JwtModule.registerAsync({
            useFactory: () => {
                const secret = process.env.JWT_SECRET;
                if (!secret || Buffer.byteLength(secret) < 32) {
                    throw new Error('JWT_SECRET debe tener al menos 32 bytes');
                }
                return {
                    secret,
                    signOptions: {
                        algorithm: 'HS256' as const,
                        expiresIn: 900,
                        issuer: 'ms-users-auth',
                        audience: 'chat-seguro',
                    },
                };
            },
        }),
    ],
    controllers: [AdminController],
    providers: [JwtAuthGuard, RolesGuard],
    exports: [JwtAuthGuard, RolesGuard],
})
export class RbacModule { }