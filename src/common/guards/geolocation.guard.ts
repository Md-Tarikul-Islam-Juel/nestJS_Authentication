import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { GeolocationService } from '../security/geolocation.service';

export const SKIP_GEO_CHECK_KEY = 'skipGeoCheck';

/**
 * Geolocation Guard
 * Blocks requests from non-allowed or blocked countries
 * Configuration from .env:
 * - GEO_ENABLED (true/false)
 * - GEO_ALLOWED_COUNTRIES (comma-separated country codes)
 */
@Injectable()
export class GeolocationGuard implements CanActivate {
    constructor(
        private readonly geoService: GeolocationService,
        private readonly reflector: Reflector,
        private readonly config: ConfigService,
    ) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        // Check if geolocation is enabled
        const geoEnabled = this.config.get<string>('GEO_ENABLED') === 'true';
        if (!geoEnabled) {
            return true; // Geolocation disabled, allow all
        }

        // Check if geo check should be skipped for this route
        const skipGeoCheck = this.reflector.getAllAndOverride<boolean>(SKIP_GEO_CHECK_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (skipGeoCheck) {
            return true;
        }

        const request = context.switchToHttp().getRequest();
        const ip = this.extractIP(request);

        const location = this.geoService.getLocation(ip);

        // Allow if location cannot be determined
        if (!location) {
            console.log(`[GeolocationGuard] Could not determine location for IP: ${ip} - allowing request`);
            return true;
        }

        console.log(`[GeolocationGuard] Request from ${location.country} (IP: ${ip})`);

        const isAllowed = await this.geoService.isCountryAllowed(location.country);
        if (!isAllowed) {
            console.log(`[GeolocationGuard] Blocking request from ${location.country} - not in allowlist`);
            throw new ForbiddenException(
                `Access denied from country: ${location.country}`,
            );
        }

        // Store location in request for later use
        request.geolocation = location;
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
