import { Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

/**
 * Throttler Guard for applications behind a proxy
 * Correctly extracts the real IP address from proxy headers
 */
@Injectable()
export class ThrottlerBehindProxyGuard extends ThrottlerGuard {
    protected async getTracker(req: Record<string, any>): Promise<string> {
        // Get real IP from proxy headers
        const forwardedFor = req.headers['x-forwarded-for'];
        if (forwardedFor) {
            // x-forwarded-for can be a comma-separated list, get the first one
            return forwardedFor.split(',')[0].trim();
        }

        // Fallback to direct IP
        return req.ips?.length ? req.ips[0] : req.ip;
    }
}
