import {Controller, Get} from '@nestjs/common';
import {ApiOperation, ApiResponse, ApiTags} from '@nestjs/swagger';
import {PrismaService} from '../platform/prisma/prisma.service';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  @Get()
  @ApiOperation({summary: 'Health check endpoint'})
  @ApiResponse({status: 200, description: 'Service is healthy'})
  async health() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString()
    };
  }

  @Get('ready')
  @ApiOperation({summary: 'Readiness check endpoint'})
  @ApiResponse({status: 200, description: 'Service is ready'})
  async ready() {
    await this.prisma.$queryRaw`SELECT 1`;
    return {
      status: 'ready',
      timestamp: new Date().toISOString()
    };
  }

  @Get('live')
  @ApiOperation({summary: 'Liveness check endpoint'})
  @ApiResponse({status: 200, description: 'Service is alive'})
  async live() {
    return {
      status: 'alive',
      timestamp: new Date().toISOString()
    };
  }
}
