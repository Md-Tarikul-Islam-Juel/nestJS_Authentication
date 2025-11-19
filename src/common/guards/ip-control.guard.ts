import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IPControlService } from '../security/ip-control.service';

export const SKIP_IP_CHECK_KEY = 'skipIpCheck';

/**
 * IP Control Guard
 * Blocks requests from non-allowed or blocked IP addresses
 */
@Injectable()
export class IPControlGuard implements CanActivate {
    constructor(
        private readonly ipControl: IPControlService,
        private readonly reflector: Reflector,
    ) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        // Check if IP check should be skipped for this route
        const skipIpCheck = this.reflector.getAllAndOverride<boolean>(SKIP_IP_CHECK_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (skipIpCheck) {
            return true;
        }

        const request = context.switchToHttp().getRequest();
        const ip = this.extractIP(request);

        const isAllowed = await this.ipControl.isIpAllowed(ip);
        if (!isAllowed) {
            const reason = await this.ipControl.getBlockReason(ip);
            throw new ForbiddenException(
                reason || 'Access denied from this IP address',
            );
        }

        return true;
    }

    private extractIP(request: any): string {
        const forwardedFor = request.headers['x-forwarded-for'];
        if (forwardedFor) {
            return forwardedFor.split(',')[0].trim();
        }
        return request.ip || 'unknown';
    }
}
