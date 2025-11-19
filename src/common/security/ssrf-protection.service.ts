import { Injectable } from '@nestjs/common';
import { URL } from 'url';

/**
 * SSRF Protection Service
 * Validates URLs to prevent Server-Side Request Forgery attacks
 */
@Injectable()
export class SSRFProtectionService {
    private readonly BLOCKED_HOSTS = [
        'localhost',
        '127.0.0.1',
        '0.0.0.0',
        '::1',
        '169.254.169.254', // AWS metadata
        '10.0.0.0/8',      // Private network
        '172.16.0.0/12',   // Private network
        '192.168.0.0/16',  // Private network
    ];

    private readonly ALLOWED_PROTOCOLS = ['http:', 'https:'];

    /**
     * Validate URL for SSRF vulnerabilities
     * @param urlString - URL to validate
     * @returns true if URL is safe, false otherwise
     */
    isUrlSafe(urlString: string): boolean {
        try {
            const url = new URL(urlString);

            // Check protocol
            if (!this.ALLOWED_PROTOCOLS.includes(url.protocol)) {
                return false;
            }

            // Check for blocked hosts
            if (this.isBlockedHost(url.hostname)) {
                return false;
            }

            // Check for IP addresses in private ranges
            if (this.isPrivateIP(url.hostname)) {
                return false;
            }

            return true;
        } catch {
            return false;
        }
    }

    private isBlockedHost(hostname: string): boolean {
        return this.BLOCKED_HOSTS.some(blocked =>
            hostname.toLowerCase().includes(blocked.toLowerCase())
        );
    }

    private isPrivateIP(hostname: string): boolean {
        // Check if it's an IP address
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(hostname)) {
            return false;
        }

        const parts = hostname.split('.').map(Number);

        // 10.0.0.0/8
        if (parts[0] === 10) return true;

        // 172.16.0.0/12
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;

        // 192.168.0.0/16
        if (parts[0] === 192 && parts[1] === 168) return true;

        // 127.0.0.0/8
        if (parts[0] === 127) return true;

        return false;
    }
}
