import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UsersModule } from '../users/users.module';
import { DatabaseModule } from '../database/database.module';
import { jwtOptions } from '../config/jwt.config';
@Module({ imports: [UsersModule, DatabaseModule, JwtModule.registerAsync({ useFactory: jwtOptions })],
  controllers: [AuthController], providers: [AuthService], exports: [AuthService] })
export class AuthModule {}
