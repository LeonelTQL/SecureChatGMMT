import { Body, Controller, Get, Param, ParseUUIDPipe, Patch, Post, Req } from '@nestjs/common';
import { RolesService } from './roles.service';
import { CreateRoleDto } from './dto/create-role.dto';
import { UpdateRoleDto } from './dto/update-role.dto';
import { Roles } from '../auth/decorators/roles/roles.decorator';
import { audit } from '../common/audit/audit';
@Roles('ADMIN') @Controller('roles')
export class RolesController {
  constructor(private readonly roles: RolesService) {}
  @Post() async create(@Body() dto: CreateRoleDto, @Req() req: any) {
    const role = await this.roles.create(dto); audit('role.created', { actor_id: req.user.sub, role_id: role.id }); return role;
  }
  @Get() findAll() { return this.roles.findAll(); }
  @Patch(':id') async update(@Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateRoleDto, @Req() req: any) {
    const role = await this.roles.update(id, dto); audit('role.updated', { actor_id: req.user.sub, role_id: id }); return role;
  }
}
