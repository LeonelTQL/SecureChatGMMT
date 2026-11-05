import { createParamDecorator, ExecutionContext } from '@nestjs/common';
export const CurrentUser = createParamDecorator((_: unknown, context: ExecutionContext) =>
  context.switchToHttp().getRequest().user);
