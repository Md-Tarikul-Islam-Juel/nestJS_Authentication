## Dependency Injection vs Dependency Inversion (with project examples)

### Concepts at a glance

- **Dependency Inversion (DIP)**: A design principle. High-level modules (business logic/application layer) should depend on abstractions, not concrete implementations. Low-level modules (infrastructure) implement those abstractions.
- **Dependency Injection (DI)**: A technique. The framework (NestJS) creates objects and supplies their dependencies (by tokens), instead of your code constructing them directly.

In short: DIP is the rule (“depend on ports”), DI is how we wire it (“bind ports to adapters and inject them”).

### In this project: Ports (abstractions)

You can swap implementations by changing only these bindings (e.g., replace `EmailServiceAdapter` with a mock adapter in tests), without touching business logic.

Practical example (Prod vs Dev) — no code, just the idea

- **Requirement**: Production must send real emails; development must avoid sending emails (no cost) and still let developers see OTPs.
- **Approach**: Keep one email port (abstraction). Provide two adapters (implementations): a real email sender for production and a mock/in-memory adapter for development.
- **DI wiring**: The environment decides which adapter is injected; the application layer does not change.
- **Outcome**:
  - Production: users receive real emails.
  - Development: OTPs are safely visible for testing (e.g., a dev-only list/log), with zero email cost.
  - Business logic stays the same because it depends only on the email port.

### How high-level code depends on ports (DIP)

Use-cases and services inject abstractions (ports) identified by tokens, not concrete classes. This is Dependency Inversion in action.

The use-case knows only about ports (`JwtServicePort`, `EmailServicePort`, etc.). Adapters are invisible to it.

### Why this matters

- Swap infrastructure without changing business code (SMTP ↔ mock, Redis provider changes, JWT library changes).
- Testability: inject fakes/mocks by token in unit tests.
- Maintainability and clarity: clean module boundaries; application layer is technology-agnostic.

### Quick mental model

- DIP: “Write your core code against interfaces (ports).”
- DI: “Let the framework supply the concrete classes (adapters) for those interfaces.”

Together, they implement a classic Ports & Adapters (Hexagonal) architecture in this project.
