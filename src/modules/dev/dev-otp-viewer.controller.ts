import { Controller, Get, HttpStatus, Post, Res, VERSION_NEUTRAL } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Response } from 'express';
import { DevOtpStorageService } from '../auth/infrastructure/cache/dev-otp-storage.service';

/**
 * Development OTP Viewer Controller
 * Provides HTML interface to view OTPs in development mode
 * ONLY accessible in development environment
 * Version-neutral to avoid /v1 prefix
 */
@Controller({path: 'dev/otps', version: VERSION_NEUTRAL})
export class DevOtpViewerController {
  private readonly isEnabled: boolean;

  constructor(
    private readonly devOtpStorage: DevOtpStorageService,
    private readonly configService: ConfigService
  ) {
    const nodeEnv = this.configService.get<string>('NODE_ENV', 'development');
    this.isEnabled = nodeEnv === 'development';
  }

  /**
   * Serve OTP viewer HTML page
   */
  @Get()
  async getViewerPage(@Res() res: Response) {
    if (!this.isEnabled) {
      return res.status(HttpStatus.NOT_FOUND).send('Not Found');
    }

    const html = this.getHtmlTemplate();
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  }

  /**
   * Get OTP data as JSON
   */
  @Get('data')
  async getOtpData(@Res() res: Response) {
    if (!this.isEnabled) {
      return res.status(HttpStatus.NOT_FOUND).json({error: 'Not Found'});
    }

    const otps = await this.devOtpStorage.getAllOtps();
    res.json(otps);
  }

  /**
   * Clear all OTPs
   */
  @Post('clear')
  async clearAllOtps(@Res() res: Response) {
    if (!this.isEnabled) {
      return res.status(HttpStatus.NOT_FOUND).json({error: 'Not Found'});
    }

    await this.devOtpStorage.clearAll();
    res.json({success: true, message: 'All OTPs cleared'});
  }

  private getHtmlTemplate(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTP Viewer - Development</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: #f5f5f5;
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            padding: 24px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        .header-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }
        
        h1 {
            font-size: 24px;
            font-weight: 600;
            color: #1a1a1a;
        }
        
        .subtitle {
            color: #666;
            font-size: 14px;
            margin-top: 4px;
        }
        
        .buttons {
            display: flex;
            gap: 12px;
        }
        
        button {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .btn-primary {
            background-color: #0066cc;
            color: white;
        }
        
        .btn-primary:hover {
            background-color: #0052a3;
        }
        
        .btn-danger {
            background-color: #dc3545;
            color: white;
        }
        
        .btn-danger:hover {
            background-color: #c82333;
        }
        
        .status-bar {
            display: flex;
            align-items: center;
            gap: 12px;
            padding-top: 16px;
            border-top: 1px solid #e0e0e0;
            font-size: 13px;
            color: #666;
        }
        
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            background-color: #28a745;
            color: white;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 500;
        }
        
        .table-container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        thead {
            background-color: #f8f9fa;
        }
        
        th {
            padding: 16px;
            text-align: left;
            font-size: 13px;
            font-weight: 600;
            color: #495057;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid #dee2e6;
        }
        
        tbody tr {
            border-bottom: 1px solid #e9ecef;
        }
        
        tbody tr:hover {
            background-color: #f8f9fa;
        }
        
        td {
            padding: 16px;
            font-size: 14px;
        }
        
        .email-cell {
            color: #212529;
            font-weight: 500;
        }
        
        .otp-code {
            font-family: 'Courier New', monospace;
            font-size: 20px;
            font-weight: 700;
            color: #0066cc;
            letter-spacing: 4px;
            cursor: pointer;
            user-select: none;
            transition: all 0.2s;
        }
        
        .otp-code:hover {
            color: #0052a3;
            transform: scale(1.05);
        }
        
        .time-cell {
            color: #6c757d;
        }
        
        .time-remaining {
            display: inline-block;
            margin-top: 4px;
            padding: 2px 8px;
            background-color: #d4edda;
            color: #155724;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 500;
        }
        
        .time-remaining.expired {
            background-color: #f8d7da;
            color: #721c24;
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
        }
        
        .empty-state-icon {
            font-size: 48px;
            margin-bottom: 16px;
            opacity: 0.5;
        }
        
        .empty-state-title {
            font-size: 18px;
            font-weight: 600;
            color: #495057;
            margin-bottom: 8px;
        }
        
        .empty-state-text {
            color: #6c757d;
            font-size: 14px;
        }
        
        .notification {
            position: fixed;
            top: 24px;
            right: 24px;
            min-width: 280px;
            padding: 16px 20px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.15), 0 0 0 1px rgba(0, 0, 0, 0.05);
            font-size: 14px;
            font-weight: 500;
            z-index: 1000;
            display: flex;
            align-items: center;
            gap: 12px;
            animation: slideInRight 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);
        }
        
        .notification.success {
            border-left: 4px solid #28a745;
        }
        
        .notification.success::before {
            content: '✓';
            display: flex;
            align-items: center;
            justify-content: center;
            width: 24px;
            height: 24px;
            background: #28a745;
            color: white;
            border-radius: 50%;
            font-weight: bold;
            font-size: 16px;
        }
        
        .notification.error {
            border-left: 4px solid #dc3545;
        }
        
        .notification.error::before {
            content: '✗';
            display: flex;
            align-items: center;
            justify-content: center;
            width: 24px;
            height: 24px;
            background: #dc3545;
            color: white;
            border-radius: 50%;
            font-weight: bold;
            font-size: 16px;
        }
        
        @keyframes slideInRight {
            from {
                transform: translateX(400px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        @keyframes slideOutRight {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(400px);
                opacity: 0;
            }
        }
        
        .hidden {
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-top">
                <div>
                    <h1>Development OTP Viewer</h1>
                    <div class="subtitle">View generated OTP codes for testing</div>
                </div>
                <div class="buttons">
                    <button class="btn-primary" onclick="refreshOtps()">Refresh</button>
                    <button class="btn-danger" onclick="clearAllOtps()">Clear All</button>
                </div>
            </div>
            <div class="status-bar">
                <span class="status-badge">DEVELOPMENT MODE</span>
                <span>Last updated: <strong id="lastUpdated">--:--:--</strong></span>
            </div>
        </div>

        <div class="table-container">
            <div id="tableWrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Email Address</th>
                            <th>OTP Code</th>
                            <th>Expires At</th>
                        </tr>
                    </thead>
                    <tbody id="otpTableBody">
                    </tbody>
                </table>
            </div>

            <div id="emptyState" class="empty-state hidden">
                <div class="empty-state-icon">📭</div>
                <div class="empty-state-title">No OTPs Generated</div>
                <div class="empty-state-text">OTPs will appear here when users register or request password reset</div>
            </div>
        </div>
    </div>

    <script>
        async function fetchOtps() {
            try {
                const response = await fetch('/dev/otps/data');
                const otps = await response.json();
                displayOtps(otps);
                updateLastUpdated();
            } catch (error) {
                console.error('Failed to fetch OTPs:', error);
            }
        }

        function displayOtps(otps) {
            const tbody = document.getElementById('otpTableBody');
            const emptyState = document.getElementById('emptyState');
            const tableWrapper = document.getElementById('tableWrapper');

            if (otps.length === 0) {
                tableWrapper.classList.add('hidden');
                emptyState.classList.remove('hidden');
                return;
            }

            tableWrapper.classList.remove('hidden');
            emptyState.classList.add('hidden');

            tbody.innerHTML = otps.map(otp => {
                const expiresAt = new Date(otp.expiresAt);
                const timeRemaining = getTimeRemaining(expiresAt);
                const isExpired = new Date() > expiresAt;
                
                return \`
                    <tr>
                        <td class="email-cell">\${otp.email}</td>
                        <td>
                            <span class="otp-code" 
                                  onclick="copyToClipboard('\${otp.otp}')" 
                                  title="Click to copy">
                                \${otp.otp}
                            </span>
                        </td>
                        <td class="time-cell">
                            <div>\${expiresAt.toLocaleString()}</div>
                            <span class="time-remaining \${isExpired ? 'expired' : ''}">
                                \${timeRemaining}
                            </span>
                        </td>
                    </tr>
                \`;
            }).join('');
        }

        function getTimeRemaining(expiresAt) {
            const now = new Date();
            const diff = expiresAt - now;
            
            if (diff <= 0) return 'Expired';
            
            const minutes = Math.floor(diff / 60000);
            const seconds = Math.floor((diff % 60000) / 1000);
            
            return \`\${minutes}m \${seconds}s remaining\`;
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showNotification('OTP copied to clipboard', 'success');
            }).catch(err => {
                console.error('Failed to copy:', err);
                showNotification('Failed to copy OTP', 'error');
            });
        }

        function showNotification(message, type = 'success') {
            const notification = document.createElement('div');
            notification.className = \`notification \${type}\`;
            
            const messageSpan = document.createElement('span');
            messageSpan.textContent = message;
            notification.appendChild(messageSpan);
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.style.animation = 'slideOutRight 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55)';
                setTimeout(() => notification.remove(), 300);
            }, 2500);
        }

        function updateLastUpdated() {
            document.getElementById('lastUpdated').textContent = new Date().toLocaleTimeString();
        }

        async function refreshOtps() {
            await fetchOtps();
            showNotification('Refreshed successfully', 'success');
        }

        async function clearAllOtps() {
            if (!confirm('Are you sure you want to clear all OTPs?')) return;
            
            try {
                await fetch('/dev/otps/clear', { method: 'POST' });
                await fetchOtps();
                showNotification('All OTPs cleared', 'success');
            } catch (error) {
                console.error('Failed to clear OTPs:', error);
                showNotification('Failed to clear OTPs', 'error');
            }
        }

        // Update countdown timers every second for real-time display
        function updateTimers() {
            const rows = document.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const timeCell = row.querySelector('.time-remaining');
                if (timeCell) {
                    const expiresAtText = row.querySelector('.time-cell div').textContent;
                    const expiresAt = new Date(expiresAtText);
                    const timeRemaining = getTimeRemaining(expiresAt);
                    const isExpired = new Date() > expiresAt;
                    
                    timeCell.textContent = timeRemaining;
                    timeCell.className = \`time-remaining \${isExpired ? 'expired' : ''}\`;
                }
            });
        }

        // Initial fetch
        fetchOtps();
        
        // Fetch new data every 5 seconds
        setInterval(fetchOtps, 5000);
        
        // Update timers every second for smooth countdown
        setInterval(updateTimers, 1000);
    </script>
</body>
</html>`;
  }
}
