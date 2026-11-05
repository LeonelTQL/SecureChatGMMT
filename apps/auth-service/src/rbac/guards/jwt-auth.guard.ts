import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Role } from '../enums/role.enum';

export interface AuthenticatedUser {
    sub: string;
    email: string;
    role: Role;
    exp: number;
}

@Injectable()
export class JwtAuthGuard implements CanActivate {
    constructor(private readonly jwtService: JwtService) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const authorization: string | undefined = request.headers?.authorization;

        const match = /^Bearer ([^\s]+)$/i.exec(authorization ?? '');
        if (!match) {
            throw new UnauthorizedException('Se requiere un token Bearer');
        }

        const token = match[1];

        try {
            const payload = await this.jwtService.verifyAsync(token, {
                algorithms: ['HS256'],
                issuer: 'ms-users-auth',
                audience: 'chat-seguro',
            });

            if (
                typeof payload.sub !== 'string' ||
                !payload.sub.trim() ||
                typeof payload.email !== 'string' ||
                !payload.email.trim() ||
                typeof payload.exp !== 'number' ||
                !Object.values(Role).includes(payload.role as Role)
            ) {
                throw new Error('Invalid JWT claims');
            }

            const user: AuthenticatedUser = {
                sub: payload.sub,
                email: payload.email,
                role: payload.role as Role,
                exp: payload.exp,
            };

            request.user = user;
            return true;
        } catch {
            throw new UnauthorizedException('Token inválido o expirado');
        }
    }
}