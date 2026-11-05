import { Controller, Get } from '@nestjs/common';
import { Roles } from '../auth/decorators/roles/roles.decorator';
@Roles('ADMIN') @Controller('admin')
export class AdminController {
  @Get('protected') protected() { return { message: 'Acceso administrativo autorizado' }; }
}
