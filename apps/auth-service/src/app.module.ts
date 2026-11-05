import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { RolesModule } from './roles/roles.module';
import { UserRolesModule } from './user-roles/user-roles.module';
import { AuthorizationModule } from './authorization/authorization.module';
import { AdminModule } from './admin/admin.module';
import { DatabaseModule } from './database/database.module';
import { AppController } from './app.controller';
import { LoginRateGuard } from './common/guards/login-rate/login-rate.guard';
import { JwtAuthGuard } from './auth/guards/jwt-auth/jwt-auth.guard';
import { RolesGuard } from './auth/guards/roles/roles.guard';
@Module({
  imports: [DatabaseModule, UsersModule, RolesModule, UserRolesModule, AuthModule, AuthorizationModule, AdminModule],
  controllers: [AppController],
  providers: [
    { provide: APP_GUARD, useClass: LoginRateGuard },
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
  ],
})
export class AppModule {}
