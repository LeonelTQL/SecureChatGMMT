import { Body, Controller, Delete, Get, HttpCode, Param, ParseUUIDPipe, Post, Query, Req } from '@nestjs/common';
import { UserRolesService } from './user-roles.service';
import { CreateUserRoleDto } from './dto/create-user-role.dto';
import { Roles } from '../auth/decorators/roles/roles.decorator';
import { audit } from '../common/audit/audit';
@Roles('ADMIN') @Controller('user-roles')
export class UserRolesController {
  constructor(private readonly assignments: UserRolesService) {}
  @Get() findAll(@Query('offset') offset?: string) { return this.assignments.findAll(offset); }
  @Post() async create(@Body() dto: CreateUserRoleDto, @Req() req: any) {
    const assignment = await this.assignments.create(dto);
    audit('role.assigned', { actor_id: req.user.sub, user_id: dto.user_id, role_id: dto.role_id }); return assignment;
  }
  @Delete(':id') @HttpCode(204)
  async remove(@Param('id', ParseUUIDPipe) id: string, @Req() req: any) {
    await this.assignments.remove(id); audit('role.unassigned', { actor_id: req.user.sub, assignment_id: id });
  }
}
