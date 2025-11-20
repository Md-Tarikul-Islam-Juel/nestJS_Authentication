import type { RequestHandler } from 'express';
import helmet from 'helmet';

const isProduction = process.env.NODE_ENV === 'production';

/**
 * Helmet middleware for security headers
 * Configures Content Security Policy and other security headers
 * In development mode, allows inline scripts for dev tools like OTP viewer
 */
export const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      scriptSrc: [
        "'self'",
        // Allow inline scripts in development mode for OTP viewer
        ...(process.env.NODE_ENV === 'development' ? ["'unsafe-inline'"] : []),
        // Allow CDN scripts (e.g., Tailwind CSS for OTP viewer)
        ...(process.env.NODE_ENV === 'development' ? ['https://cdn.tailwindcss.com'] : [])
      ],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      fontSrc: ["'self'", 'https:', 'data:'],
      connectSrc: ["'self'", 'https:'],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      // Allow inline event handlers (onclick) in development mode for OTP viewer
      scriptSrcAttr: process.env.NODE_ENV === 'development' ? ["'unsafe-inline'"] : ["'none'"],
      upgradeInsecureRequests: isProduction ? [] : null
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: {policy: 'same-origin'},
  crossOriginResourcePolicy: {policy: 'same-origin'},
  frameguard: {action: 'deny'},
  dnsPrefetchControl: {allow: false},
  referrerPolicy: {policy: 'no-referrer'},
  hidePoweredBy: true,
  hsts: isProduction
    ? {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    : false,
  originAgentCluster: true,
  permittedCrossDomainPolicies: {permittedPolicies: 'none'}
});

const permissionsPolicyHeader =
  'accelerometer=(), autoplay=(), camera=(), clipboard-read=(), ' +
  'display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), ' +
  'magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), ' +
  'screen-wake-lock=(), sync-xhr=(), usb=(), vr=(), xr-spatial-tracking=()';


export const permissionsPolicyMiddleware: RequestHandler = (req, res, next) => {
  res.setHeader('Permissions-Policy', permissionsPolicyHeader);
  next();
};

export const securityHeadersMiddleware = [helmetMiddleware, permissionsPolicyMiddleware];
