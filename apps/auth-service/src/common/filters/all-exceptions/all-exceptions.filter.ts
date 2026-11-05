import { ArgumentsHost, Catch, ExceptionFilter, HttpException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
@Catch()
export class SafeErrors implements ExceptionFilter {
  catch(error: unknown, host: ArgumentsHost) {
    const response = host.switchToHttp().getResponse();
    let status = 500, message: unknown = 'Error interno';
    if (error instanceof HttpException) { status = error.getStatus(); message = error.getResponse(); }
    else if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === 'P2002') { status = 409; message = 'El registro ya existe'; }
      if (error.code === 'P2025') { status = 404; message = 'Recurso no encontrado'; }
      if (error.code === 'P2003') { status = 400; message = 'Usuario o rol inexistente'; }
    }
    console.log(JSON.stringify({ event: 'request.rejected', status, timestamp: new Date().toISOString() }));
    response.status(status).json(typeof message === 'object' ? message : { statusCode: status, message });
  }
}
