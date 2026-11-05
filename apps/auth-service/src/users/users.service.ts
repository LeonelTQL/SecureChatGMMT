import { ConflictException, Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../database/prisma.service';
import { hashPassword } from '../common/security/password';
import { offsetPage } from '../common/dto/pagination-query.dto/pagination-query.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User, userFields } from './entities/user.entity';
@Injectable()
export class UsersService {
  constructor(private readonly db: PrismaService) {}
  async create(dto: CreateUserDto): Promise<User> {
    const passwordHash = await hashPassword(dto.password);
    try {
      return await this.db.user.create({ data: { username: dto.username, email: dto.email, passwordHash }, select: userFields });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') throw new ConflictException('Usuario o correo ya registrado');
      throw error;
    }
  }
  findAll(offset?: string): Promise<User[]> {
    return this.db.user.findMany({ select: userFields, take: 100, skip: offsetPage(offset), orderBy: { createdAt: 'asc' } });
  }
  findForAuthentication(email: string) { return this.db.user.findUnique({ where: { email } }); }
  update(id: string, dto: UpdateUserDto): Promise<User> {
    return this.db.$transaction(async tx => {
      const user = await tx.user.update({ where: { id }, data: dto, select: userFields });
      if (dto.status === false) await tx.session.updateMany({ where: { userId: id }, data: { revoked: true } });
      return user;
    });
  }
}
