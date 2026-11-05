import {
    CanActivate,
    ExecutionContext,
    ForbiddenException,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { Role } from '../enums/role.enum';
import { AuthenticatedUser } from './jwt-auth.guard';

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(private readonly reflector: Reflector) { }

    canActivate(context: ExecutionContext): boolean {
        const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (!requiredRoles || requiredRoles.length === 0) {
            return true;
        }

        const request = context.switchToHttp().getRequest();
        const user: AuthenticatedUser | undefined = request.user;

        if (!user || !user.role) {
            throw new UnauthorizedException('Usuario no autenticado');
        }

        const hasPermission = requiredRoles.includes(user.role);
        if (!hasPermission) {
            throw new ForbiddenException(
                'No tienes permisos suficientes para acceder a este recurso',
            );
        }

        return true;
    }
}