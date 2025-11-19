# Security Policy

## Dependency Integrity

All dependencies are locked with exact versions in `package-lock.json`.

### Verification
```bash
npm ci --ignore-scripts
```

### Updates
Only update dependencies through:
1. Dependabot PRs
2. Manual review + testing
3. Security patches

## Code Signing

### Commits
All commits must be signed with GPG:
```bash
git config commit.gpgsign true
```

### Releases
All releases are tagged and signed:
```bash
git tag -s v1.0.0 -m "Release v1.0.0"
```
