import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import { offsetPage } from '../common/dto/pagination-query.dto/pagination-query.dto';
import { CreateUserRoleDto } from './dto/create-user-role.dto';
import type { UserRole } from './entities/user-role.entity';
@Injectable()
export class UserRolesService {
  constructor(private readonly db: PrismaService) {}
  create(dto: CreateUserRoleDto): Promise<UserRole> { return this.db.userRole.create({ data: { userId: dto.user_id, roleId: dto.role_id } }); }
  findAll(offset?: string): Promise<UserRole[]> {
    return this.db.userRole.findMany({ take: 100, skip: offsetPage(offset), orderBy: { assignedAt: 'asc' } });
  }
  async remove(id: string): Promise<void> { await this.db.userRole.delete({ where: { id } }); }
}
