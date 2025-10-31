# Cleanup Plan - Remove Old Structure Files

## ✅ Safe to Remove (New Structure in Place)

### 1. Old Platform Services

- ❌ `src/modules/prisma/` → Replaced by `src/platform/prisma/`
- ❌ `src/modules/redis/` → Replaced by `src/platform/redis/`
- ❌ `src/modules/logger/` → Replaced by `src/common/observability/logger.*`
- ❌ `src/modules/filter/` → Replaced by `src/common/http/filters/problem-details.filter.ts`

### 2. Old Auth Module Structure (Legacy)

- ❌ `src/modules/auth/controllers/` → Replaced by `src/modules/auth/interface/http/`
- ❌ `src/modules/auth/dtos/` → Replaced by `src/modules/auth/application/dto/`
- ❌ `src/modules/auth/services/` → Replaced by Clean Architecture layers
- ❌ `src/modules/auth/Interceptor/` → Replaced by `src/modules/auth/interface/http/interceptors/`

### 3. Old User Module (Keep DTOs, Remove Rest)

- ⚠️ `src/modules/user/user.module.ts` → Replaced by `src/modules/users/users.module.ts`
- ⚠️ `src/modules/user/resolver/` → Replaced by `src/modules/users/interface/graphql/`
- ⚠️ `src/modules/user/services/` → Replaced by `src/modules/users/application/services/`
- ✅ `src/modules/user/dto/` → **KEEP** (used by new users module for GraphQL types)

## 🔄 Files to Check Before Removal

Some old files might still be referenced. Check these:

- `src/modules/auth/services/auth.service.ts` (old location) - might be used
- `src/modules/auth/services/*.service.ts` - check if referenced
- `src/modules/user/resolver/user.resolver.ts` - replaced by users.resolver.ts

## 📋 Cleanup Commands

```bash
# Remove old platform services
rm -rf src/modules/prisma
rm -rf src/modules/redis
rm -rf src/modules/logger
rm -rf src/modules/filter

# Remove old auth structure (after verifying no references)
rm -rf src/modules/auth/controllers
rm -rf src/modules/auth/dtos
rm -rf src/modules/auth/Interceptor
# Keep services/ for now until verified

# Remove old user module (keep dto/)
rm -rf src/modules/user/user.module.ts
rm -rf src/modules/user/resolver
rm -rf src/modules/user/services
# Keep: src/modules/user/dto/
```

## ⚠️ Important Notes

1. **Test First**: Run the application and verify all endpoints work
2. **Check Imports**: Search for any remaining references to old paths
3. **Keep DTOs**: The old `src/modules/user/dto/` folder should remain as it contains GraphQL types used by the new users module
4. **Legacy Services**: Some services in `src/modules/auth/services/` are still referenced by the application service - keep for now
