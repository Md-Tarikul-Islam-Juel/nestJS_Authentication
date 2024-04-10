import {
    ArgumentsHost,
    BadRequestException,
    Catch, ConflictException,
    ExceptionFilter,
    ForbiddenException,
    HttpException,
    HttpStatus,
    NotFoundException,
    UnauthorizedException,
} from '@nestjs/common';
import {Prisma} from '@prisma/client';
import {ValidationError} from 'class-validator';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
    catch(exception: unknown, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse();
        const request = ctx.getRequest();

        const status = HttpStatus.INTERNAL_SERVER_ERROR;
        const message = 'Internal Server Error';

        if (exception instanceof Prisma.PrismaClientKnownRequestError) {
            // Handle Prisma errors here

            // Example: Check for a unique constraint violation
            if (exception.code === 'P2002') {
                return response.status(200).json({
                    success: false,
                    message: `${exception.meta.target[0]} already exists`,
                });
            } else if (exception.code === 'P2025') {
                return response.status(200).json({
                    success: false,
                    message: "Resource doesn't exist or you don't have permission",
                });
            } else if (exception.code === 'P2003') {
                return response.status(status).json({
                    success: false,
                    message: 'Error on deleting the resource',
                });
            }
            // Handle other Prisma error codes as needed...
        } else if (exception instanceof Prisma.PrismaClientValidationError) {
            return response.status(200).json({
                success: false,
                message: 'Validation Error',
            });
        } else if (exception instanceof HttpException) {
            if (exception instanceof NotFoundException) {
                return response.status(200).json({
                    success: false,
                    message: exception.message,
                });
            } else if (exception instanceof BadRequestException) {
                return response.status(400).json({
                    success: false,
                    message: exception.message,
                });
            } else if (exception instanceof UnauthorizedException) {
                return response.status(401).json({
                    success: false,
                    message: exception.message,
                });
            } else if (exception instanceof ForbiddenException) {
                return response.status(403).json({
                    success: false,
                    message: exception.message,
                });
            } else if (exception instanceof ConflictException) {
                return response.status(HttpStatus.CONFLICT).json({
                    success: false,
                    message: exception.message,
                });
            }
        } else {
            return response.status(200).json({
                success: false,
                message: 'Internal server error',
            });
        }
    }
}
