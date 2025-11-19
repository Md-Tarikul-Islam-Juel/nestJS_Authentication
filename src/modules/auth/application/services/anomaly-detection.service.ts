import { Injectable, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '../../../../platform/redis/redis.service';
import { EMAIL_SERVICE_PORT, LOGGER_PORT } from '../di-tokens';
import type { EmailServicePort } from '../../domain/repositories/email.service.port';
import type { LoggerPort } from '../../domain/repositories/logger.port';

/**
 * Login Attempt Interface
 */
export interface LoginAttempt {
    ip: string;
    userAgent: string;
    timestamp: Date;
    location?: {
        country?: string;
        city?: string;
        latitude?: number;
        longitude?: number;
    };
    deviceFingerprint?: string;
}

/**
 * Anomaly Detection Result
 */
export interface AnomalyResult {
    isSuspicious: boolean;
    reasons: string[];
    riskScore: number; // 0-100
    shouldBlock: boolean;
    shouldRequireMFA: boolean;
}

/**
 * Anomaly Detection Service
 * 
 * Detects suspicious login patterns including:
 * - New device detection
 * - Impossible travel (rapid location changes)
 * - Unusual login times
 * - Velocity attacks (too many attempts)
 * - IP reputation checking
 * 
 * Risk Scoring:
 * - 0-30: Low risk (allow)
 * - 31-60: Medium risk (require MFA)
 * - 61-100: High risk (block and alert)
 */
@Injectable()
export class AnomalyDetectionService {
    private readonly LOGIN_HISTORY_SIZE = 10;
    private readonly LOGIN_HISTORY_TTL = 2592000; // 30 days
    private readonly VELOCITY_WINDOW = 300; // 5 minutes
    private readonly MAX_ATTEMPTS_PER_WINDOW = 5;

    constructor(
        private readonly redis: RedisService,
        private readonly configService: ConfigService,
        @Inject(EMAIL_SERVICE_PORT)
        private readonly emailService: EmailServicePort,
        @Inject(LOGGER_PORT)
        private readonly logger: LoggerPort,
    ) { }

    /**
     * Analyze login attempt for suspicious patterns
     */
    async analyzeLoginAttempt(
        userId: number,
        email: string,
        attempt: LoginAttempt,
    ): Promise<AnomalyResult> {
        const reasons: string[] = [];
        let riskScore = 0;

        // Get login history
        const history = await this.getLoginHistory(userId);

        // 1. Check for velocity attacks
        const velocityCheck = await this.checkVelocity(userId);
        if (velocityCheck.isViolation) {
            reasons.push('Too many login attempts in short time');
            riskScore += 40;
        }

        // 2. Check for new device
        if (this.isNewDevice(attempt, history)) {
            reasons.push('Login from new device');
            riskScore += 20;
        }

        // 3. Check for new location
        if (this.isNewLocation(attempt, history)) {
            reasons.push('Login from new location');
            riskScore += 15;
        }

        // 4. Check for impossible travel
        if (this.isImpossibleTravel(attempt, history)) {
            reasons.push('Impossible travel detected');
            riskScore += 50;
        }

        // 5. Check for unusual time
        if (this.isUnusualTime(attempt, history)) {
            reasons.push('Login at unusual time');
            riskScore += 10;
        }

        // 6. Check IP reputation
        const ipReputation = await this.checkIPReputation(attempt.ip);
        if (ipReputation.isSuspicious) {
            reasons.push(`Suspicious IP: ${ipReputation.reason}`);
            riskScore += ipReputation.riskScore;
        }

        // 7. Check device fingerprint
        if (attempt.deviceFingerprint && this.isNewFingerprint(attempt, history)) {
            reasons.push('New device fingerprint detected');
            riskScore += 15;
        }

        // Store this attempt
        await this.storeLoginAttempt(userId, attempt);

        // Determine action based on risk score
        const isSuspicious = riskScore > 30;
        const shouldBlock = riskScore > 60;
        const shouldRequireMFA = riskScore > 30 && riskScore <= 60;

        // Send alert if high risk
        if (shouldBlock) {
            await this.sendSecurityAlert(userId, email, attempt, reasons, riskScore);
        }

        // Log the analysis
        this.logger.warn({
            message: 'Login anomaly detected',
            details: {
                userId,
                email,
                riskScore,
                reasons,
                shouldBlock,
                ip: attempt.ip,
            },
        });

        return {
            isSuspicious,
            reasons,
            riskScore,
            shouldBlock,
            shouldRequireMFA,
        };
    }

    /**
     * Get login history for user
     */
    private async getLoginHistory(userId: number): Promise<LoginAttempt[]> {
        const key = this.getHistoryKey(userId);
        const history = await this.redis.lrange(key, 0, this.LOGIN_HISTORY_SIZE - 1);

        return history.map((item) => JSON.parse(item));
    }

    /**
     * Store login attempt in history
     */
    private async storeLoginAttempt(
        userId: number,
        attempt: LoginAttempt,
    ): Promise<void> {
        const key = this.getHistoryKey(userId);
        await this.redis.lpush(key, JSON.stringify(attempt));
        await this.redis.ltrim(key, 0, this.LOGIN_HISTORY_SIZE - 1);
        await this.redis.expire(key, this.LOGIN_HISTORY_TTL);
    }

    /**
     * Check for velocity attacks (too many attempts in short time)
     */
    private async checkVelocity(
        userId: number,
    ): Promise<{ isViolation: boolean; count: number }> {
        const key = `velocity:${userId}`;
        const count = await this.redis.incr(key);

        if (count === 1) {
            await this.redis.expire(key, this.VELOCITY_WINDOW);
        }

        return {
            isViolation: count > this.MAX_ATTEMPTS_PER_WINDOW,
            count,
        };
    }

    /**
     * Check if login is from a new device
     */
    private isNewDevice(attempt: LoginAttempt, history: LoginAttempt[]): boolean {
        if (history.length === 0) return false;

        return !history.some((h) => h.userAgent === attempt.userAgent);
    }

    /**
     * Check if login is from a new location
     */
    private isNewLocation(attempt: LoginAttempt, history: LoginAttempt[]): boolean {
        if (!attempt.location || history.length === 0) return false;

        return !history.some(
            (h) =>
                h.location?.country === attempt.location?.country &&
                h.location?.city === attempt.location?.city,
        );
    }

    /**
     * Check for impossible travel
     * If user logged in from different location within impossible timeframe
     */
    private isImpossibleTravel(
        attempt: LoginAttempt,
        history: LoginAttempt[],
    ): boolean {
        if (!attempt.location || history.length === 0) return false;

        const lastLogin = history[0];
        if (!lastLogin.location) return false;

        const timeDiff =
            new Date(attempt.timestamp).getTime() -
            new Date(lastLogin.timestamp).getTime();
        const hoursDiff = timeDiff / (1000 * 60 * 60);

        // Calculate distance between locations
        const distance = this.calculateDistance(
            lastLogin.location.latitude || 0,
            lastLogin.location.longitude || 0,
            attempt.location.latitude || 0,
            attempt.location.longitude || 0,
        );

        // If distance > 500km and time < 1 hour, it's impossible travel
        // Average flight speed is ~800 km/h, but accounting for airport time
        const maxPossibleDistance = hoursDiff * 800;

        return distance > maxPossibleDistance && distance > 500;
    }

    /**
     * Calculate distance between two coordinates (Haversine formula)
     */
    private calculateDistance(
        lat1: number,
        lon1: number,
        lat2: number,
        lon2: number,
    ): number {
        const R = 6371; // Earth's radius in km
        const dLat = this.toRad(lat2 - lat1);
        const dLon = this.toRad(lon2 - lon1);

        const a =
            Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(this.toRad(lat1)) *
            Math.cos(this.toRad(lat2)) *
            Math.sin(dLon / 2) *
            Math.sin(dLon / 2);

        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    }

    private toRad(degrees: number): number {
        return (degrees * Math.PI) / 180;
    }

    /**
     * Check if login time is unusual for this user
     */
    private isUnusualTime(attempt: LoginAttempt, history: LoginAttempt[]): boolean {
        if (history.length < 5) return false; // Need enough data

        const hour = new Date(attempt.timestamp).getHours();

        // Calculate user's typical login hours
        const loginHours = history.map((h) => new Date(h.timestamp).getHours());
        const avgHour =
            loginHours.reduce((sum, h) => sum + h, 0) / loginHours.length;

        // If login is more than 6 hours different from average, it's unusual
        const hourDiff = Math.abs(hour - avgHour);
        return hourDiff > 6 && hourDiff < 18; // Account for 24-hour wrap
    }

    /**
     * Check if device fingerprint is new
     */
    private isNewFingerprint(
        attempt: LoginAttempt,
        history: LoginAttempt[],
    ): boolean {
        if (!attempt.deviceFingerprint || history.length === 0) return false;

        return !history.some((h) => h.deviceFingerprint === attempt.deviceFingerprint);
    }

    /**
     * Check IP reputation against known malicious IPs
     */
    private async checkIPReputation(
        ip: string,
    ): Promise<{ isSuspicious: boolean; reason: string; riskScore: number }> {
        // Check if IP is in blocklist
        const isBlocked = await this.redis.sismember('ip:blocklist', ip);
        if (isBlocked) {
            return {
                isSuspicious: true,
                reason: 'IP in blocklist',
                riskScore: 60,
            };
        }

        // Check if IP has too many failed attempts
        const failedAttempts = await this.redis.get(`ip:failed:${ip}`);
        if (failedAttempts && parseInt(failedAttempts) > 10) {
            return {
                isSuspicious: true,
                reason: 'Too many failed attempts from this IP',
                riskScore: 30,
            };
        }

        // Check if IP is from known VPN/proxy (optional - requires external service)
        // const isVPN = await this.checkVPNService(ip);

        return {
            isSuspicious: false,
            reason: '',
            riskScore: 0,
        };
    }

    /**
   * Send security alert to user
   * TODO: Implement proper security alert email template in EmailServicePort
   */
    private async sendSecurityAlert(
        userId: number,
        email: string,
        attempt: LoginAttempt,
        reasons: string[],
        riskScore: number,
    ): Promise<void> {
        try {
            // For now, log the security alert
            // TODO: Add sendSecurityAlert method to EmailServicePort interface
            this.logger.warn({
                message: 'Security alert - suspicious login detected',
                details: {
                    userId,
                    email,
                    riskScore,
                    reasons,
                    ip: attempt.ip,
                    location: attempt.location,
                    timestamp: attempt.timestamp,
                },
            });

            // Optionally send a generic email using existing OTP infrastructure
            // You can enhance this by adding a proper security alert template
            /*
            await this.emailService.sendOtpEmail(
              email,
              `Security Alert: Suspicious login attempt detected. Risk score: ${riskScore}. Reasons: ${reasons.join(', ')}`,
              60
            );
            */
        } catch (error) {
            this.logger.error({
                message: 'Failed to log security alert',
                details: {
                    userId,
                    email,
                    error: error instanceof Error ? error.message : String(error),
                },
            });
        }
    }

    /**
     * Block an IP address
     */
    async blockIP(ip: string, reason: string, durationSeconds?: number): Promise<void> {
        await this.redis.sadd('ip:blocklist', ip);

        if (durationSeconds) {
            // Temporary block
            await this.redis.set(`ip:block:reason:${ip}`, reason, durationSeconds);
        } else {
            // Permanent block (use very long TTL: 10 years)
            await this.redis.set(`ip:block:reason:${ip}`, reason, 315360000);
        }

        this.logger.warn({
            message: 'IP blocked',
            details: { ip, reason, durationSeconds },
        });
    }

    /**
     * Unblock an IP address
     */
    async unblockIP(ip: string): Promise<void> {
        await this.redis.srem('ip:blocklist', ip);
        await this.redis.del(`ip:block:reason:${ip}`);

        this.logger.info({
            message: 'IP unblocked',
            details: { ip },
        });
    }

    /**
     * Record failed login attempt for IP
     */
    async recordFailedAttempt(ip: string): Promise<void> {
        const key = `ip:failed:${ip}`;
        const count = await this.redis.incr(key);

        if (count === 1) {
            await this.redis.expire(key, 3600); // 1 hour
        }

        // Auto-block after 20 failed attempts
        if (count >= 20) {
            await this.blockIP(ip, 'Too many failed login attempts', 7200); // 2 hours
        }
    }

    /**
     * Get Redis key for login history
     */
    private getHistoryKey(userId: number): string {
        return `user:${userId}:login_history`;
    }
}
