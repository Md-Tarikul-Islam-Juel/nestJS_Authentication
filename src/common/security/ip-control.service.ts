import { Injectable } from '@nestjs/common';
import { RedisService } from '../../platform/redis/redis.service';

/**
 * IP Control Service
 * Manages IP allowlisting and blocklisting
 */
@Injectable()
export class IPControlService {
    private readonly ALLOWLIST_KEY = 'ip:allowlist';
    private readonly BLOCKLIST_KEY = 'ip:blocklist';

    constructor(private readonly redis: RedisService) { }

    /**
     * Check if an IP address is allowed to access the application
     * 
     * @param ip - The IP address to check
     * @returns Promise resolving to true if allowed, false if blocked
     * 
     * @remarks
     * - First checks if IP is in blocklist (immediate rejection)
     * - Then checks if allowlist is active
     * - If allowlist is active, IP must be in it
     * - If allowlist is empty/inactive, IP is allowed
     */
    async isIpAllowed(ip: string): Promise<boolean> {
        const isBlocked = await this.redis.sismember(this.BLOCKLIST_KEY, ip);
        if (isBlocked) {
            return false;
        }

        const allowlistCount = await this.redis.scard(this.ALLOWLIST_KEY);
        if (allowlistCount > 0) {
            const isAllowed = await this.redis.sismember(this.ALLOWLIST_KEY, ip);
            return isAllowed;
        }

        return true;
    }

    /**
     * Add an IP address to the allowlist
     * 
     * @param ip - The IP address to allow
     * @returns Promise resolving when operation is complete
     */
    async allowIp(ip: string): Promise<void> {
        await this.redis.sadd(this.ALLOWLIST_KEY, ip);
    }

    /**
     * Remove an IP address from the allowlist
     * 
     * @param ip - The IP address to remove from allowlist
     * @returns Promise resolving when operation is complete
     */
    async removeAllowedIp(ip: string): Promise<void> {
        await this.redis.srem(this.ALLOWLIST_KEY, ip);
    }

    /**
     * Add an IP address to the blocklist
     * 
     * @param ip - The IP address to block
     * @param reason - Optional reason for blocking the IP
     * @returns Promise resolving when operation is complete
     */
    async blockIp(ip: string, reason?: string): Promise<void> {
        await this.redis.sadd(this.BLOCKLIST_KEY, ip);
        if (reason) {
            await this.redis.set(`ip:block:reason:${ip}`, reason, 2592000); // 30 days
        }
    }

    /**
     */
    async removeFromBlocklist(ip: string): Promise<void> {
        await this.redis.srem(this.BLOCKLIST_KEY, ip);
        await this.redis.del(`ip:block:reason:${ip}`);
    }

    /**
     * Get block reason for an IP
     */
    async getBlockReason(ip: string): Promise<string | null> {
        return await this.redis.get(`ip:block:reason:${ip}`);
    }

    /**
     * Get allowlist size
     */
    private async getAllowlistSize(): Promise<number> {
        const keys = await this.redis.keys(`${this.ALLOWLIST_KEY}`);
        return keys.length;
    }

    /**
     * Check if IP is blocked
     */
    async isBlocked(ip: string): Promise<boolean> {
        return await this.redis.sismember(this.BLOCKLIST_KEY, ip);
    }
}
