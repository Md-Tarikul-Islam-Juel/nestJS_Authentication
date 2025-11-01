# Logging Best Practices - NestJS

## Overview

The application now uses an **enhanced LoggerService** that follows NestJS best practices while maintaining backward compatibility with the existing codebase.

## Key Features

### ✅ NestJS Logger Interface Compliance

- Implements `LoggerService` interface from `@nestjs/common`
- Supports all standard NestJS logger methods: `log()`, `error()`, `warn()`, `debug()`, `verbose()`

### ✅ Structured Logging with Winston

- Uses Winston for structured JSON logging
- Separate log files for errors, combined logs, exceptions, and rejections
- Environment-aware formatting (colored output in development)

### ✅ Enhanced Log Format

```typescript
// Standard NestJS format
logger.error('Error message', 'Context', stackTrace, details);

// Backward compatible legacy format (still works)
logger.error({message: 'Error message', details: {...}});
```

## Log File Structure

```
logs/
  ├── error.log          # Error level logs only
  ├── combined.log       # All logs
  ├── exceptions.log     # Unhandled exceptions
  └── rejections.log     # Unhandled promise rejections
```

## Usage Examples

### Standard NestJS Pattern (Recommended)

```typescript
// Error with context and stack trace
this.logger.error('Authentication failed', 'AuthService.authenticate()', error.stack, {userId: 123, email: 'user@example.com'});

// Info log
this.logger.info('User successfully authenticated', 'AuthService.authenticate()');

// Warning
this.logger.warn('Rate limit approaching', 'RateLimitService.checkLimit()', undefined, {requests: 95, limit: 100});

// Debug (only in development)
this.logger.debug('Processing request', 'RequestInterceptor.intercept()', undefined, {method: 'POST', path: '/auth/signin'});
```

### Legacy Format (Still Supported)

```typescript
// Old format still works for backward compatibility
this.logger.error({
  message: 'Error occurred',
  details: {userId: 123}
});
```

## Best Practices

### 1. Always Provide Context

```typescript
// ✅ Good
this.logger.error('Failed to save user', 'UserService.save()', stack, {userId: 123});

// ❌ Bad
this.logger.error('Failed to save user');
```

### 2. Include Stack Traces for Errors

```typescript
// ✅ Good
this.logger.error('Database error', 'DatabaseService.query()', error.stack, {query: 'SELECT...'});

// ❌ Bad (missing stack)
this.logger.error('Database error', 'DatabaseService.query()', undefined, {query: 'SELECT...'});
```

### 3. Use Appropriate Log Levels

- **error**: Errors that need immediate attention
- **warn**: Warnings that don't stop execution but should be monitored
- **info**: Important business events (user signup, payments, etc.)
- **debug**: Detailed debugging information (development only)
- **verbose**: Most detailed logs (development only)

### 4. Sanitize Sensitive Data

```typescript
// ✅ Good - Remove sensitive data
this.logger.error('Authentication failed', 'AuthService.authenticate()', undefined, this.removeSensitiveData(user, ['password', 'token']));

// ❌ Bad - Logs sensitive data
this.logger.error('Authentication failed', 'AuthService.authenticate()', undefined, {password: user.password});
```

### 5. Use Context for Traceability

```typescript
// Context format: ClassName.methodName()
this.logger.error('Error message', 'UserService.authenticateUser()', stack, details);
```

## Configuration

Set log level via environment variable:

```bash
LOG_LEVEL=debug    # development
LOG_LEVEL=info     # production (default)
LOG_LEVEL=warn     # production (minimal)
LOG_LEVEL=error    # production (errors only)
```

## Log Output Format

### Development (Console)

```
2025-11-01 15:22:12 +00:00 [error] [UserService.authenticateUser()] Authentication failed. Invalid password for user user@example.com {"userId":1,"email":"user@example.com"}
```

### Production (JSON)

```json
{
  "timestamp": "2025-11-01 15:22:12 +00:00",
  "level": "error",
  "message": "Authentication failed. Invalid password for user user@example.com",
  "context": "UserService.authenticateUser()",
  "details": {
    "userId": 1,
    "email": "user@example.com"
  },
  "stack": "Error: ...",
  "service": "nestjs-authentication",
  "environment": "production"
}
```

## Migration from Old Format

Old format (still works):

```typescript
this.logger.error({
  message: 'Error message',
  details: {key: 'value'}
});
```

New format (recommended):

```typescript
this.logger.error('Error message', 'ContextName.method()', stackTrace, {key: 'value'});
```

## Benefits

1. **Structured Logging**: JSON format for easy parsing by log aggregation tools
2. **Traceability**: Context shows exactly where log originated
3. **Stack Traces**: Automatic capture and formatting
4. **File Organization**: Separate files for different log levels
5. **Environment Aware**: Different formatting for dev vs production
6. **NestJS Compliance**: Follows official NestJS logging patterns
7. **Backward Compatible**: Old format still works
