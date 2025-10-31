# Naming Conventions

## Naming Conventions (NestJS + Prisma, Clean Architecture)

This project follows **Clean Architecture**, **DDD tactical patterns**, and **DIP**.  
Naming must clearly communicate **responsibility, layer, and lifecycle**.

---

## 1) Global Rules

| Thing                  | Convention                                   | Examples                                    |
| ---------------------- | -------------------------------------------- | ------------------------------------------- |
| Folders & Files        | `kebab-case`                                 | `user-profile/`, `register-user.usecase.ts` |
| Classes / Types        | `PascalCase`                                 | `User`, `PasswordPolicyService`, `UserView` |
| Functions / Variables  | `camelCase`                                  | `hashPassword()`, `userService`             |
| Constants              | `SCREAMING_SNAKE_CASE`                       | `MAX_PAGE_LIMIT`, `HTTP_TIMEOUT_MS`         |
| Enums                  | `PascalCase` + `SCREAMING_SNAKE_CASE` values | `Role.ADMIN`, `UserStatus.ACTIVE`           |
| Tests                  | Mirror SUT + `.spec.ts`                      | `register-user.usecase.spec.ts`             |
| Migrations / SQL files | Timestamped kebab                            | `20251030T112233-add-user-table.sql`        |

---

## 2) Bounded Context / Module Naming

```
modules/
  users/
  auth/
  billing/
```

✅ Always **plural nouns**.  
❌ Avoid: `user-management/`, `authorization-system/`

---

## 3) Clean Architecture Layer Naming

| Layer              | Folder            | Naming Rules                                                                       | Example                     |
| ------------------ | ----------------- | ---------------------------------------------------------------------------------- | --------------------------- |
| **Domain**         | `domain/`         | `.entity.ts`, `.vo.ts`, `.service.ts`, `.event.ts`, `.repository.port.ts`          | `user.entity.ts`            |
| **Application**    | `application/`    | `.usecase.ts`, `.dto.ts`, `.view.ts`, `.mapper.ts`, `.uow.port.ts`                 | `register-user.usecase.ts`  |
| **Infrastructure** | `infrastructure/` | `.prisma.repository.ts`, `.prisma.mapper.ts`, `.uow.ts`, `.cache.ts`, `.outbox.ts` | `user.prisma.repository.ts` |
| **Interface**      | `interface/`      | `.controller.ts`, `.schema.ts`, `.presenter.ts`                                    | `users.controller.ts`       |

---

## 4) Domain Layer Naming

| Item            | File Pattern                    | Example                         |
| --------------- | ------------------------------- | ------------------------------- |
| Entity          | `<resource>.entity.ts`          | `user.entity.ts`                |
| Value Object    | `<concept>.vo.ts`               | `email.vo.ts`, `password.vo.ts` |
| Domain Service  | `<rule>-policy.service.ts`      | `password-policy.service.ts`    |
| Domain Event    | `<event>.event.ts`              | `user-registered.event.ts`      |
| Repository Port | `<resource>.repository.port.ts` | `user.repository.port.ts`       |
| Domain Error    | `<condition>.error.ts`          | `email-already-taken.error.ts`  |

---

## 5) Application Layer Naming

| Item              | File Pattern                   | Example                     |
| ----------------- | ------------------------------ | --------------------------- |
| Write Use Case    | `<verb>-<resource>.usecase.ts` | `register-user.usecase.ts`  |
| Read Use Case     | `<query>.usecase.ts`           | `get-user-by-id.usecase.ts` |
| Input DTO         | `<action>.dto.ts`              | `register-user.dto.ts`      |
| Output View       | `<resource>.view.ts`           | `user.view.ts`              |
| Mapper            | `<resource>.mapper.ts`         | `user.mapper.ts`            |
| Unit of Work Port | `uow.port.ts`                  | `uow.port.ts`               |

---

## 6) Infrastructure Layer Naming

| Adapter Type              | File Pattern                      | Example                     |
| ------------------------- | --------------------------------- | --------------------------- |
| Repository Implementation | `<resource>.prisma.repository.ts` | `user.prisma.repository.ts` |
| ORM Mapper                | `<resource>.prisma.mapper.ts`     | `user.prisma.mapper.ts`     |
| UoW Implementation        | `prisma.uow.ts`                   | `prisma.uow.ts`             |
| Cache Adapter             | `<resource>.cache.ts`             | `user.cache.ts`             |
| Outbox Store              | `<resource>.outbox.ts`            | `user.outbox.ts`            |

---

## 7) Interface / HTTP Layer Naming

| Item             | File Pattern               | Example                   |
| ---------------- | -------------------------- | ------------------------- |
| Controller       | `<resource>.controller.ts` | `users.controller.ts`     |
| Validator Schema | `<action>.schema.ts`       | `register-user.schema.ts` |
| Presenter        | `<resource>.presenter.ts`  | `users.presenter.ts`      |

---

## 8) REST API Naming

| Rule                       | ✅ Correct             | ❌ Wrong          |
| -------------------------- | ---------------------- | ----------------- |
| Resource nouns are plural  | `/users`               | `/user`           |
| No verbs in URLs           | `/sessions`            | `/login`          |
| Use `kebab-case`           | `/customer-orders`     | `/customerOrders` |
| Nested relations use nouns | `/users/{id}/sessions` | `/sessionsByUser` |

---

## 9) Event Naming

- Events use **past tense** → `user-registered.event.ts`
- Event handlers mirror event name → `user-registered.handler.ts`

---

## 10) Commit Style (Conventional Commits)

```
feat: add register-user use case
fix: correct prisma rollback behavior
refactor: extract password-policy service
docs: update naming conventions
```
