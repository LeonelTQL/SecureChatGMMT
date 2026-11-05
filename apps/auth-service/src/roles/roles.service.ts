import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import { CreateRoleDto } from './dto/create-role.dto';
import { UpdateRoleDto } from './dto/update-role.dto';
import type { Role } from './entities/role.entity';
@Injectable()
export class RolesService {
  constructor(private readonly db: PrismaService) {}
  create(dto: CreateRoleDto): Promise<Role> { return this.db.role.create({ data: dto }); }
  findAll(): Promise<Role[]> { return this.db.role.findMany({ orderBy: { name: 'asc' }, take: 100 }); }
  update(id: string, dto: UpdateRoleDto): Promise<Role> { return this.db.role.update({ where: { id }, data: dto }); }
}
