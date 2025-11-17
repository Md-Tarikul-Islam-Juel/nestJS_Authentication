import {VersioningOptions, VersioningType} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';

/**
 * API Versioning Configuration
 * Supports multiple versioning strategies: URL, Header, or both
 * Configure via environment variables for easy control
 */
export interface VersioningConfig {
  /** Enable or disable versioning globally */
  enabled: boolean;
  /** Versioning strategy: 'uri' | 'header' | 'media-type' */
  type: VersioningType;
  /** Default version when none specified */
  defaultVersion: string | string[];
  /** Header name for header-based versioning (e.g., 'X-API-Version') */
  headerName?: string;
  /** Media type key for media-type versioning (e.g., 'v') */
  mediaTypeKey?: string;
}

/**
 * Create versioning configuration from environment variables
 */
export function createVersioningConfig(configService: ConfigService): VersioningConfig {
  const enabled = (configService.get<string>('API_VERSIONING_ENABLED') ?? 'true').toLowerCase() === 'true';
  const typeStr = (configService.get<string>('API_VERSIONING_TYPE') ?? 'uri').toLowerCase();

  // Map string to VersioningType enum
  let type: VersioningType;
  if (typeStr === 'header') {
    type = VersioningType.HEADER;
  } else if (typeStr === 'media-type') {
    type = VersioningType.MEDIA_TYPE;
  } else {
    type = VersioningType.URI;
  }

  const defaultVersion = configService.get<string>('API_DEFAULT_VERSION') ?? '1';
  const headerName = configService.get<string>('API_VERSION_HEADER_NAME') ?? 'X-API-Version';
  const mediaTypeKey = configService.get<string>('API_VERSION_MEDIA_TYPE_KEY') ?? 'v';

  return {
    enabled,
    type,
    defaultVersion: defaultVersion.split(',').map(v => v.trim()),
    headerName,
    mediaTypeKey
  };
}

/**
 * Create NestJS versioning options
 */
export function createVersioningOptions(config: VersioningConfig): VersioningOptions | undefined {
  if (!config.enabled) {
    return undefined;
  }

  // Base options
  const baseOptions = {
    type: config.type,
    defaultVersion: config.defaultVersion
  };

  // Add type-specific options
  if (config.type === VersioningType.HEADER && config.headerName) {
    return {
      ...baseOptions,
      header: config.headerName
    } as VersioningOptions;
  }

  if (config.type === VersioningType.MEDIA_TYPE && config.mediaTypeKey) {
    return {
      ...baseOptions,
      key: config.mediaTypeKey
    } as VersioningOptions;
  }

  // URI versioning (default)
  return baseOptions as VersioningOptions;
}
