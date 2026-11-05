import { Controller, Get } from '@nestjs/common';
import { Public } from './auth/decorators/public/public.decorator';
import { PrismaService } from './database/prisma.service';
@Controller()
export class AppController {
  constructor(private readonly db: PrismaService) {}
  @Public() @Get('health')
  async health() { await this.db.$queryRaw`SELECT 1`; return { service: 'ms-users-auth', status: 'ok' }; }
}
