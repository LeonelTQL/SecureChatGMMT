import { Controller, Get, Module } from '@nestjs/common';
@Controller()
class HealthController {
  @Get('health')
  status() { return { service: 'chat-service', status: 'ok', implementation: 'scaffold' }; }
}
@Module({ controllers: [HealthController] })
export class AppModule {}
