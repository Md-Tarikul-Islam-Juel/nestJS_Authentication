# API Versioning Guide

This project implements comprehensive API versioning with multiple strategies and easy configuration.

## Configuration

Control versioning via environment variables in your `.env` file:

```env
# Enable/disable versioning (default: true)
API_VERSIONING_ENABLED=true

# Versioning strategy: 'uri' | 'header' | 'media-type' (default: 'uri')
API_VERSIONING_TYPE=uri

# Default version when none specified (default: '1')
# Can specify multiple versions: '1,2'
API_DEFAULT_VERSION=1

# Header name for header-based versioning (default: 'X-API-Version')
API_VERSION_HEADER_NAME=X-API-Version

# Media type key for media-type versioning (default: 'v')
API_VERSION_MEDIA_TYPE_KEY=v
```

## Versioning Strategies

### 1. URI Versioning (Default)

URLs include the version prefix:

- `GET /v1/auth/signup`
- `GET /v2/auth/signup`

**Configuration:**

```env
API_VERSIONING_TYPE=uri
```

### 2. Header Versioning

Version specified in HTTP header:

```bash
curl -H "X-API-Version: 1" http://localhost:3000/auth/signup
```

**Configuration:**

```env
API_VERSIONING_TYPE=header
API_VERSION_HEADER_NAME=X-API-Version
```

### 3. Media-Type Versioning

Version in Accept header:

```bash
curl -H "Accept: application/json;v=1" http://localhost:3000/auth/signup
```

**Configuration:**

```env
API_VERSIONING_TYPE=media-type
API_VERSION_MEDIA_TYPE_KEY=v
```

## Using Versions in Controllers

### Controller-Level Versioning

```typescript
import {API_VERSIONS} from '../../../../common/http/version.constants';

@Controller({
  path: 'auth',
  version: [API_VERSIONS.V1, API_VERSIONS.V2] // Supports both v1 and v2
})
export class AuthController {
  // All routes inherit controller version
}
```

### Route-Level Versioning

```typescript
import {Version} from '@nestjs/common';
import {API_VERSIONS} from '../../../../common/http/version.constants';

@Controller('auth')
export class AuthController {
  @Version(API_VERSIONS.V1)
  @Get('signup')
  signupV1() {
    // v1 implementation
  }

  @Version(API_VERSIONS.V2)
  @Get('signup')
  signupV2() {
    // v2 implementation
  }
}
```

## Version Management

### Adding New Versions

1. Update `src/common/http/version.constants.ts`:

```typescript
export const API_VERSIONS = {
  V1: '1',
  V2: '2',
  V3: '3' // Add new version
} as const;
```

2. Update version metadata:

```typescript
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
```

### Deprecating Versions

When a version is deprecated, the `VersionDeprecationInterceptor` automatically adds headers:

- `Deprecation: true`
- `Sunset: <date>`
- `Link: <migration-guide>; rel="deprecation"`
- `X-API-Version-Status: deprecated`

## Examples

### URI Versioning

```bash
# v1 endpoint
curl http://localhost:3000/v1/auth/signup

# v2 endpoint
curl http://localhost:3000/v2/auth/signup
```

### Header Versioning

```bash
# v1 endpoint
curl -H "X-API-Version: 1" http://localhost:3000/auth/signup

# v2 endpoint
curl -H "X-API-Version: 2" http://localhost:3000/auth/signup
```

### Media-Type Versioning

```bash
# v1 endpoint
curl -H "Accept: application/json;v=1" http://localhost:3000/auth/signup

# v2 endpoint
curl -H "Accept: application/json;v=2" http://localhost:3000/auth/signup
```

## Best Practices

1. **Always support the default version** - Set `API_DEFAULT_VERSION` to your current stable version
2. **Deprecate gracefully** - Mark old versions as deprecated before removing them
3. **Provide migration guides** - Include links in version metadata
4. **Document breaking changes** - Clearly communicate what changed between versions
5. **Use semantic versioning** - Consider major.minor.patch if needed (requires custom implementation)

## Disabling Versioning

To disable versioning entirely:

```env
API_VERSIONING_ENABLED=false
```

All routes will work without version prefixes/headers.
