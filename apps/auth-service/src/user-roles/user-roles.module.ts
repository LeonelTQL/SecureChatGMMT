import { Module } from '@nestjs/common';
import { UserRolesController } from './user-roles.controller';
import { UserRolesService } from './user-roles.service';
import { DatabaseModule } from '../database/database.module';
@Module({ imports: [DatabaseModule], controllers: [UserRolesController], providers: [UserRolesService], exports: [UserRolesService] })
export class UserRolesModule {}
