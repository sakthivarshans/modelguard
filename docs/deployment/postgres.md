# PostgreSQL registry: deployment guide

Install: `pip install "modelguard[postgres]"`. Requires PostgreSQL 13+
(developed and tested against 16).

## 1. Two roles

| Role | Purpose | Privileges |
| --- | --- | --- |
| `mg_owner` | Runs migrations; owns the tables | DDL on the registry database |
| `mg_app` | Used by `verify`, `register`, `revoke`, `admit()` | see below |

```sql
-- as mg_owner, after `modelguard registry migrate`
CREATE ROLE mg_app LOGIN PASSWORD '...';
GRANT SELECT, INSERT ON registry_records, revocation_events TO mg_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO mg_app;
GRANT SELECT ON modelguard_schema_migrations TO mg_app;
```

The runtime role cannot alter or delete history and cannot migrate
(both covered by tests). Never run the application as `mg_owner`: an
owner can disable the append-only triggers.

## 2. Connection strings

* Put the DSN in an environment variable and pass its **name**:
  `modelguard verify ... --registry-dsn-env MG_REGISTRY_DSN`.
  Never put a DSN on a command line (visible to other local users).
* The DSN must name a `host` explicitly (ambient `PGHOST` is ignored).
* Any non-local host requires `sslmode=verify-full` (or `verify-ca`).
  `require` and weaker are refused: they encrypt but do not authenticate
  the server, so a network attacker could forge "not revoked".

```
host=db.internal.example.com dbname=modelguard user=mg_app password=... sslmode=verify-full sslrootcert=/etc/ssl/db-ca.pem
```

## 3. Migrations

```bash
export MG_OWNER_DSN='host=... user=mg_owner ... sslmode=verify-full'
modelguard registry migrate --dsn-env MG_OWNER_DSN
```

Migrations are checksummed. ModelGuard refuses to run against a schema
whose applied migration differs from what it ships, or one that is
newer than itself.

## 4. Integrity checking

```bash
modelguard registry verify-chain --dsn-env MG_REGISTRY_DSN   # 0 intact, 2 tampered
```

Run it on a schedule. It detects edits and mid-chain deletions; it
cannot detect removal of the most recent events.

## 5. Failure behavior

Any database problem (outage, timeout, permissions, bad schema) makes
`verify` exit 1 and `admit()` deny. It is never treated as "not
revoked".

## 6. Running the PostgreSQL tests

```bash
export MODELGUARD_TEST_POSTGRES_DSN='host=localhost dbname=postgres user=<role with CREATEDB and CREATEROLE> password=...'
pytest -rs
```

Without the variable those tests are reported as skipped.
