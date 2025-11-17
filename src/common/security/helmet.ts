import {NextFunction, Request, Response} from 'express';
import helmet from 'helmet';

const isProduction = process.env.NODE_ENV === 'production';

const contentSecurityPolicy = {
  directives: {
    defaultSrc: ["'self'"],
    baseUri: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:', 'https:'],
    fontSrc: ["'self'", 'https:', 'data:'],
    connectSrc: ["'self'", 'https:'],
    objectSrc: ["'none'"],
    frameAncestors: ["'none'"],
    formAction: ["'self'"],
    upgradeInsecureRequests: isProduction ? [] : null
  }
};

const permissionsPolicyHeader =
  'accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), ' +
  'display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), ' +
  'magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), ' +
  'screen-wake-lock=(), sync-xhr=(), usb=(), vr=(), xr-spatial-tracking=()';

export const helmetMiddleware = helmet({
  contentSecurityPolicy,
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

export const permissionsPolicyMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  res.setHeader('Permissions-Policy', permissionsPolicyHeader);
  next();
};

export const securityHeadersMiddleware = [helmetMiddleware, permissionsPolicyMiddleware];
