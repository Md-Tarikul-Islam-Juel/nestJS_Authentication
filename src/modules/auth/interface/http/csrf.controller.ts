import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { Request } from 'express';
import { AccessTokenStrategy } from '../../../../common/auth/strategies/access-token.strategy';
import { CsrfGuard } from '../../../../common/guards/csrf.guard';

/**
 * CSRF Token Controller
 * 
 * Provides endpoints for CSRF token management
 */
@ApiTags('Security')
@Controller('security')
export class CsrfController {
    constructor(private readonly csrfGuard: CsrfGuard) { }

    /**
     * Get CSRF token for authenticated user
     * 
     * Usage:
     * 1. Call this endpoint after login
     * 2. Store token in memory (not localStorage)
     * 3. Include token in X-CSRF-Token header for all state-changing requests
     */
    @Get('csrf-token')
    @UseGuards(AccessTokenStrategy)
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Get CSRF token',
        description: 'Generates a CSRF token for the authenticated user. Include this token in the X-CSRF-Token header for all POST/PUT/PATCH/DELETE requests.',
    })
    @ApiResponse({
        status: 200,
        description: 'CSRF token generated successfully',
        schema: {
            type: 'object',
            properties: {
                csrfToken: {
                    type: 'string',
                    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6',
                },
                expiresIn: {
                    type: 'number',
                    example: 3600,
                    description: 'Token expiry time in seconds',
                },
            },
        },
    })
    @ApiResponse({
        status: 401,
        description: 'Unauthorized - Invalid or missing access token',
    })
    async getCsrfToken(@Req() req: Request): Promise<{
        csrfToken: string;
        expiresIn: number;
    }> {
        const userId = (req as any).user.id;
        const csrfToken = await this.csrfGuard.generateToken(userId);

        return {
            csrfToken,
            expiresIn: 3600, // 1 hour
        };
    }

    /**
     * Revoke CSRF token (called on logout)
     */
    @Get('csrf-token/revoke')
    @UseGuards(AccessTokenStrategy)
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Revoke CSRF token',
        description: 'Revokes the current CSRF token. Typically called during logout.',
    })
    @ApiResponse({
        status: 200,
        description: 'CSRF token revoked successfully',
    })
    async revokeCsrfToken(@Req() req: Request): Promise<{ success: boolean }> {
        const userId = (req as any).user.id;
        await this.csrfGuard.revokeToken(userId);

        return { success: true };
    }
}
