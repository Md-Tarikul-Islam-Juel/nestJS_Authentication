/**
 * API Version Constants
 * Centralized version management for easy updates
 */

/**
 * Supported API versions
 * Add new versions here when releasing new API versions
 */
export const API_VERSIONS = {
  V1: '1',
  V2: '2',
  V3: '3'
} as const;

/**
 * Current default API version
 * Update this when deprecating old versions
 */
export const DEFAULT_API_VERSION = API_VERSIONS.V1;

/**
 * All supported versions as array
 */
export const SUPPORTED_VERSIONS = Object.values(API_VERSIONS);

/**
 * Version metadata for documentation and deprecation notices
 */
export interface VersionMetadata {
  version: string;
  status: 'current' | 'deprecated' | 'sunset';
  deprecatedAt?: string;
  sunsetAt?: string;
  migrationGuide?: string;
}

/**
 * Version status registry
 */
export const VERSION_METADATA: Record<string, VersionMetadata> = {
  [API_VERSIONS.V1]: {
    version: API_VERSIONS.V1,
    status: 'current'
  },
  [API_VERSIONS.V2]: {
    version: API_VERSIONS.V2,
    status: 'deprecated',
    deprecatedAt: '2024-01-01',
    migrationGuide: 'https://docs.example.com/migration/v1-to-v2'
  }
};

/**
 * Get version metadata
 */
export function getVersionMetadata(version: string): VersionMetadata | undefined {
  return VERSION_METADATA[version];
}

/**
 * Check if version is deprecated
 */
export function isVersionDeprecated(version: string): boolean {
  const metadata = getVersionMetadata(version);
  return metadata?.status === 'deprecated' || metadata?.status === 'sunset';
}
