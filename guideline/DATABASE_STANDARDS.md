# Database Standards

## 💾 Database (Prisma)

**Unit of Work (UoW):** central transaction boundary  
(keywords: $transaction, atomicity, commit/rollback, isolation level, retry, timeout)

**API:** uow.withTransaction(fn: (tx: Prisma.TransactionClient) => Promise<T>)  
(keywords: closure, context propagation, single responsibility, idempotent use-case)

**Tx-Scoped Repository:** repo.withTx(tx) returns a repo bound to that tx  
(keywords: port & adapter, DIP, testability, savepoint-like scoping)

---

## Data & Storage (Prisma-focused)

**Optimistic locking:** version/updatedAt + WHERE version = ?.

**Soft delete** + unique constraints that ignore soft-deleted rows.

**PII taxonomy:** tag columns by sensitivity; masking/redaction at ORM & log layers.

**Monetary/decimal:** use DECIMAL + minor units; never float.

**Migrations:** gated in CI (dry-run + backup check); rollout with feature flags.

**Backups & DR:** RPO/RTO targets; PITR; restore drills.

**Multi-tenancy strategy:** by column with RLS or by schema/database—decide early.
