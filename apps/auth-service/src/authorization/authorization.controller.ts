import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { ServiceOnly } from '../auth/decorators/service-only/service-only.decorator';
import { AuthorizationService } from './authorization.service';
import { AuthorizationCheckDto } from './dto/authorization-check.dto';
@Controller('internal/authorization')
export class AuthorizationController {
  constructor(private readonly authorization: AuthorizationService) {}
  @ServiceOnly() @Post('check') @HttpCode(200)
  check(@Body() dto: AuthorizationCheckDto) { return this.authorization.check(dto); }
}
