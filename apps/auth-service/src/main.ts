import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { readFileSync } from 'node:fs';
import { SwaggerModule } from '@nestjs/swagger';
import { authOpenApi } from './config/openapi';
import { SafeErrors } from './common/filters/all-exceptions/all-exceptions.filter';
async function bootstrap() {
  const app = await NestFactory.create(AppModule, { httpsOptions: {
    key: readFileSync(process.env.TLS_KEY_PATH ?? '/run/keys/tls-key.pem'),
    cert: readFileSync(process.env.TLS_CERT_PATH ?? '/run/keys/tls-cert.pem'),
  } });
  app.setGlobalPrefix('api', { exclude: ['health', 'internal/authorization/check'] });
  app.getHttpAdapter().getInstance().set('trust proxy', 0);
  app.getHttpAdapter().getInstance().disable('x-powered-by');
  app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true, forbidNonWhitelisted: true }));
  app.useGlobalFilters(new SafeErrors());
  SwaggerModule.setup('docs', app, authOpenApi);
  app.enableShutdownHooks();
  await app.listen(Number(process.env.PORT || 3001), '0.0.0.0');
}
bootstrap();
