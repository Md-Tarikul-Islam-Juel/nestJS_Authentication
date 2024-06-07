// import {
//     ArgumentsHost,
//     BadRequestException,
//     Catch, ConflictException,
//     ExceptionFilter,
//     ForbiddenException,
//     HttpException,
//     HttpStatus,
//     NotFoundException,
//     UnauthorizedException,
// } from '@nestjs/common';
// import {Prisma} from '@prisma/client';
//
//
// @Catch()
// export class AllExceptionsFilter implements ExceptionFilter {
//     catch(exception: unknown, host: ArgumentsHost) {
//         const ctx = host.switchToHttp();
//         const response = ctx.getResponse();
//         const request = ctx.getRequest();
//
//         const status = HttpStatus.INTERNAL_SERVER_ERROR;
//         const message = 'Internal Server Error';
//
//         if (exception instanceof Prisma.PrismaClientKnownRequestError) {
//             if (exception.code === 'P2002') {
//                 return response.status(200).json({
//                     success: false,
//                     message: `${exception.meta.target[0]} already exists`,
//                 });
//             } else if (exception.code === 'P2025') {
//                 return response.status(200).json({
//                     success: false,
//                     message: "Resource doesn't exist or you don't have permission",
//                 });
//             } else if (exception.code === 'P2003') {
//                 return response.status(status).json({
//                     success: false,
//                     message: 'Error on deleting the resource',
//                 });
//             }
//             // Handle other Prisma error codes as needed...
//         } else if (exception instanceof Prisma.PrismaClientValidationError) {
//             return response.status(200).json({
//                 success: false,
//                 message: 'Validation Error',
//             });
//         } else if (exception instanceof HttpException) {
//             if (exception instanceof NotFoundException) {
//                 return response.status(200).json({
//                     success: false,
//                     message: exception.message,
//                 });
//             } else if (exception instanceof BadRequestException) {
//                 return response.status(400).json({
//                     success: false,
//                     message: exception.message,
//                 });
//             } else if (exception instanceof UnauthorizedException) {
//                 return response.status(401).json({
//                     success: false,
//                     message: exception.message,
//                 });
//             } else if (exception instanceof ForbiddenException) {
//                 return response.status(403).json({
//                     success: false,
//                     message: exception.message,
//                 });
//             } else if (exception instanceof ConflictException) {
//                 return response.status(HttpStatus.CONFLICT).json({
//                     success: false,
//                     message: exception.message,
//                 });
//             }
//         } else {
//             return response.status(200).json({
//                 success: false,
//                 message: 'Internal server error',
//             });
//         }
//     }
// }


import {
    ArgumentsHost,
    Catch,
    ExceptionFilter,
    HttpException,
    HttpStatus,
    NotFoundException,
    BadRequestException,
    UnauthorizedException,
    ForbiddenException,
    ConflictException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaClientInitializationError } from '@prisma/client/runtime/library';


@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
    catch(exception: unknown, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse();
        const request = ctx.getRequest();

        const status = exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;
        const message = exception instanceof HttpException ? exception.getResponse() : 'Internal Server Error';

        if (exception instanceof Prisma.PrismaClientKnownRequestError) {
            if (exception.code === 'P2002') {
                return response.status(HttpStatus.CONFLICT).json({
                    success: false,
                    message: `${exception.meta.target[0]} already exists`,
                });
            } else if (exception.code === 'P2025') {
                return response.status(HttpStatus.NOT_FOUND).json({
                    success: false,
                    message: "Resource doesn't exist or you don't have permission",
                });
            } else if (exception.code === 'P2003') {
                return response.status(HttpStatus.BAD_REQUEST).json({
                    success: false,
                    message: 'Error on deleting the resource',
                });
            }
            // Handle other Prisma error codes as needed...
        } else if (exception instanceof Prisma.PrismaClientValidationError) {
            return response.status(HttpStatus.BAD_REQUEST).json({
                success: false,
                message: 'Validation Error',
            });
        } else if (exception instanceof PrismaClientInitializationError) {
            return response.status(HttpStatus.SERVICE_UNAVAILABLE).json({
                success: false,
                message: 'Database connection error',
            });
        } else if (exception instanceof HttpException) {
            if (exception instanceof NotFoundException) {
                return response.status(HttpStatus.NOT_FOUND).json({
                    success: false,
                    message: exception.message,
                });
            } else if (exception instanceof BadRequestException) {
                return response.status(HttpStatus.BAD_REQUEST).json({
                    success: false,
                    message: exception.message,
                });
            } else if (exception instanceof UnauthorizedException) {
                return response.status(HttpStatus.UNAUTHORIZED).json({
                    success: false,
                    message: exception.message,
                });
            } else if (exception instanceof ForbiddenException) {
                return response.status(HttpStatus.FORBIDDEN).json({
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
            return response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
                success: false,
                message: 'Internal server error',
            });
        }
    }
}
