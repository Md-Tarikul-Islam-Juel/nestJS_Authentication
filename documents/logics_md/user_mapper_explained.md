# Understanding `UserMapper`

## Why do we need a mapper?

When we build an app we usually split it into layers so every part has a clear job:

- **Domain layer**: holds business rules. Our `User` entity lives here. It uses rich types (for example an `Email` value object that validates the address).
- **Application layer**: glues use-cases together and decides what to send back to the outside world.
- **Interface layer**: controllers/GraphQL resolvers that finally return JSON to the client.

Each layer should speak its own language. The domain talks in domain objects, but the outside world expects simple plain-data objects (DTOs). A mapper sits in the middle and translates from the domain language to the DTO language.

## What does `UserMapper` do?

`UserMapper` has two helper functions:

1. `toSignInResponse` – used when a user signs in.
2. `toSignupResponse` – used right after a user registers.

Both helpers take a `User` domain object and return a DTO (data transfer object) that only contains the fields a client should see: `id`, `email`, `firstName`, `lastName`.

```text
Domain User (rich object)
        │
        ▼
   UserMapper (translation step)
        │
        ▼
SignIn / Signup DTO (plain JSON-ready object)
```

## Why is this important?

- **Protects rules**: the domain object can have validation logic, but the DTO is just data. Mapping stops outside code from bypassing the rules.
- **Prevents leaks**: if the domain ever contains sensitive fields (password hashes, logout pins, etc.), the mapper keeps them out of the response on purpose.
- **Keeps changes local**: if the domain entity or the DTO shape changes, we only update the mapper. Controllers and use-cases stay clean.
- **Improves tests**: we can test the mapper separately to make sure responses always have the correct format.

## When should I use it?

- Any time a use-case needs to return a response DTO based on a domain entity.
- Any time we add new response types—create a new mapper method instead of reshaping objects inline.

## Quick mental model

Think of the mapper like a translator. Your business logic speaks “Domain”, your frontend speaks “DTO”. The mapper is the one who makes sure both sides understand each other without mixing their internal details.
