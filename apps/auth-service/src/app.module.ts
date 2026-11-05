import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { DatabaseModule } from './database/database.module';
import { AppController } from './app.controller';
import { LoginRateGuard } from './common/guards/login-rate/login-rate.guard';
import { AuthenticationGuard } from './auth/guards/authentication.guard';
@Module({
  imports: [DatabaseModule, UsersModule, AuthModule],
  controllers: [AppController],
  providers: [
    { provide: APP_GUARD, useClass: LoginRateGuard },
    { provide: APP_GUARD, useClass: AuthenticationGuard },
  ],
})
export class AppModule {}
