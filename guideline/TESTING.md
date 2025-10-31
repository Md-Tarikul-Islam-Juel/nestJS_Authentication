# Testing

## 🧮 Testing

**Test Pyramid** →  
Focus on Unit → Integration → E2E hierarchy.  
(Keywords: fast feedback, isolation, deterministic tests, mocking, test doubles, automation, TDD/BDD).

- **Unit Tests** → isolate logic (jest, vitest), mock I/O.
- **Integration Tests** → real DB, API, or external service boundaries.
- **E2E Tests** → simulate full user flow via supertest / playwright.

**Contract Testing (OpenAPI / Pact)** →  
Verify client–server compatibility against OpenAPI schema before deployment.  
(Keywords: schema validation, backward compatibility, consumer-driven contract testing, API governance).

**Pre-commit Hooks** →  
Enforce quality before code lands.  
(Keywords: lint-staged, husky, commitlint, conventional commits, pre-push tests, git hygiene).  
Example: run eslint, prettier, npm test, and type-check pre-commit.

**Static Analysis / Lint / Format** →  
Automate with ESLint, Prettier, TypeScript strict mode, and SonarQube.  
(Keywords: code quality, type safety, maintainability, readability, consistency).
