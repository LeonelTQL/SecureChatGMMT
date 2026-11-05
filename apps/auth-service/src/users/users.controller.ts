import { Body, Controller, Get, Param, ParseUUIDPipe, Patch, Post, Query, Req } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { Roles } from '../auth/decorators/roles/roles.decorator';
import { audit } from '../common/audit/audit';
@Roles('ADMIN') @Controller('users')
export class UsersController {
  constructor(private readonly users: UsersService) {}
  @Post() async create(@Body() dto: CreateUserDto, @Req() req: any) {
    const user = await this.users.create(dto); audit('user.created', { actor_id: req.user.sub, user_id: user.id }); return user;
  }
  @Get() findAll(@Query('offset') offset?: string) { return this.users.findAll(offset); }
  @Patch(':id') async update(@Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateUserDto, @Req() req: any) {
    const user = await this.users.update(id, dto); audit('user.updated', { actor_id: req.user.sub, user_id: id }); return user;
  }
}
