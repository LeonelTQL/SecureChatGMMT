import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { Roles } from '../decorators/roles.decorator';
import { Role } from '../enums/role.enum';
import { AuthenticatedUser, JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';

@Controller('admin')
@UseGuards(JwtAuthGuard, RolesGuard)
export class AdminController {
    @Get('protected')
    @Roles(Role.ADMIN)
    getProtectedResource(@Req() request: { user: AuthenticatedUser }) {
        return {
            message: 'Acceso concedido al recurso administrativo',
            user: request.user,
        };
    }
}