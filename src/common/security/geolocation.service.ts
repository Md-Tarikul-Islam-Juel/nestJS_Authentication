import { Injectable, OnModuleInit } from '@nestjs/common';
import * as geoip from 'geoip-lite';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '../../platform/redis/redis.service';

export interface LocationInfo {
    country: string;
    region: string;
    city: string;
    latitude: number;
    longitude: number;
    timezone: string;
}

/**
 * Geolocation Service
 * Provides geolocation-based access control
 * Automatically loads allowed countries from GEO_ALLOWED_COUNTRIES on startup
 */
@Injectable()
export class GeolocationService implements OnModuleInit {
    private readonly ALLOWED_COUNTRIES_KEY = 'geo:allowed_countries';
    private readonly BLOCKED_COUNTRIES_KEY = 'geo:blocked_countries';

    constructor(
        private readonly redis: RedisService,
        private readonly config: ConfigService,
    ) { }

    async onModuleInit() {
        // Clear existing allowlist to sync with .env
        await this.clearAllowlist();

        // Load allowed countries from .env on startup
        const allowedCountries = this.config.get<string>('GEO_ALLOWED_COUNTRIES');
        if (allowedCountries) {
            const countries = allowedCountries.split(',').map(c => c.trim().toUpperCase());
            for (const country of countries) {
                await this.addAllowedCountry(country);
            }
            console.log(`[GeolocationService] Loaded ${countries.length} allowed countries from .env: ${countries.join(', ')}`);
        } else {
            console.log('[GeolocationService] No GEO_ALLOWED_COUNTRIES configured - allowing all countries');
        }
    }

    /**
     * Clear the entire allowlist
     */
    private async clearAllowlist(): Promise<void> {
        await this.redis.del(this.ALLOWED_COUNTRIES_KEY);
    }

    /**
     * Get location information from IP address
     * 
     * @param ip - The IP address to lookup
     * @returns LocationInfo object or null if lookup fails
     */
    getLocation(ip: string): LocationInfo | null {
        const geo = geoip.lookup(ip);
        if (!geo) return null;

        return {
            country: geo.country,
            region: geo.region,
            city: geo.city,
            latitude: geo.ll[0],
            longitude: geo.ll[1],
            timezone: geo.timezone,
        };
    }

    /**
     * Check if a country is allowed to access the application
     * 
     * @param countryCode - Two-letter ISO country code (e.g., 'US', 'BD')
     * @returns Promise resolving to true if allowed, false if blocked
     * 
     * @remarks
     * - First checks if country is in blocklist (immediate rejection)
     * - Then checks if allowlist is active
     * - If allowlist is active, country must be in it
     * - If allowlist is empty/inactive, country is allowed
     */
    async isCountryAllowed(countryCode: string): Promise<boolean> {
        const isBlocked = await this.redis.sismember(this.BLOCKED_COUNTRIES_KEY, countryCode);
        if (isBlocked) {
            return false;
        }

        const allowlistCount = await this.redis.scard(this.ALLOWED_COUNTRIES_KEY);
        if (allowlistCount > 0) {
            const isAllowed = await this.redis.sismember(this.ALLOWED_COUNTRIES_KEY, countryCode);
            return isAllowed;
        }

        return true;
    }

    /**
     * Add a country to the allowlist
     * 
     * @param countryCode - Two-letter ISO country code
     */
    async addAllowedCountry(countryCode: string): Promise<void> {
        await this.redis.sadd(this.ALLOWED_COUNTRIES_KEY, countryCode.toUpperCase());
    }

    /**
     * Remove a country from the allowlist
     * 
     * @param countryCode - Two-letter ISO country code
     */
    async removeAllowedCountry(countryCode: string): Promise<void> {
        await this.redis.srem(this.ALLOWED_COUNTRIES_KEY, countryCode.toUpperCase());
    }

    /**
     * Add a country to the blocklist
     * 
     * @param countryCode - Two-letter ISO country code
     */
    async blockCountry(countryCode: string): Promise<void> {
        await this.redis.sadd(this.BLOCKED_COUNTRIES_KEY, countryCode.toUpperCase());
    }

    /**
     * Remove a country from the blocklist
     * 
     * @param countryCode - Two-letter ISO country code
     */
    /**
     * Remove a country from the blocklist
     * 
     * @param countryCode - Two-letter ISO country code
     */
    async unblockCountry(countryCode: string): Promise<void> {
        await this.redis.srem(this.BLOCKED_COUNTRIES_KEY, countryCode.toUpperCase());
    }
}
