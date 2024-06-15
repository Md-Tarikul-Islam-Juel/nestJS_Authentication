import { Controller, Get, HttpCode, HttpStatus, Inject, Req, UseGuards } from '@nestjs/common';
import { ME } from '../utils/string';
import { UserService } from '../services/user.service';
import { Request } from 'express';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { MeSuccessResponseDto } from '../dto/userRespnse.dto';
import { JweJwtAccessTokenStrategy } from '../../jwe-jwt/jwe-jwt-access-token.strategy';

@ApiTags('User')
@Controller('user')
export class UserController {
  constructor(
    @Inject(UserService)
    private readonly userService: UserService,
  ) {
  }

  @HttpCode(HttpStatus.OK)
  @Get(ME)
  @UseGuards(JweJwtAccessTokenStrategy)
  @ApiOperation({ summary: 'Get user data' })
  @ApiOkResponse({ description: 'Get user data', type: MeSuccessResponseDto })
  async me(@Req() req: Request) {
    return await this.userService.me(req);
  }
}
