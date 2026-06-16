# Native Aurora IAM / SSO auth for the DBeaver MCP server

**Date:** 2026-06-16
**Status:** Design approved, pending implementation plan
**Repo:** `omnisql-mcp` (formerly `dbeaver-mcp-server`), v2.0.x
**Base branch:** `feat/export-output-path` — the active development line. The auth
work lands on `feat/mcp-aurora-iam-auth`, branched on top of it.

## Problem

The MCP server bypasses DBeaver entirely: it reads DBeaver's stored connection
config + decrypted credentials and connects directly via native clients (the
`pg` client for PostgreSQL, `mysql2` for MySQL, etc.).

For an **Aurora IAM** connection there is no usable stored password — the
password is a short-lived RDS IAM auth token that must be minted on demand from
an AWS profile, and the underlying AWS SSO (IAM Identity Center) session may be
expired and require an interactive browser login. Today the MCP finds no
password, so the query fails with a raw connection error.

Goal: when a connection needs auth, the MCP request should **not** hard-fail.
Instead it should (a) silently mint a fresh token when a valid AWS/SSO session
exists, and (b) when the SSO session is expired, surface a structured
"auth required" signal so the model can ask the user to log in (via an explicit
login tool) or skip — rather than crashing.

## Scope

- **In scope:** AWS IAM database authentication for **Aurora PostgreSQL** via
  AWS SSO profiles. Silent token minting + an explicit SSO-login MCP tool.
  **Postgres only for this plan** (user decision).
- **Out of scope:** Aurora **MySQL** (same RDS Signer; a fast-follow, not this plan);
  non-AWS auth mechanisms; generic credential refresh; driving DBeaver's own
  UI/SSO wizard. A pluggable provider interface is explicitly *not* required
  (decided during brainstorming).

## Verified facts about the environment

Confirmed against the user's real DBeaver workspace and the MCP source.

### MCP architecture (on `feat/export-output-path`)
- The native-client module is **`src/workspace-client.ts`** (renamed from
  `dbeaver-client.ts` on this branch). `executeWithNativeTool()` routes by
  `connection.driver.toLowerCase()` and **already matches Aurora**:
  `d.includes('postgres') || (d.includes('aurora') && d.includes('postgres'))`
  → `executePostgreSQLQuery` (workspace-client.ts:~181/197). So `aurora_pg_prod`
  (`driver: aurora-postgresql`) already routes to the Postgres path — **no routing
  change needed**.
- `executePostgreSQLQuery` (workspace-client.ts:~271) connects with
  `new Client({ host, port, database, user, password, ssl })`, where
  `user = connection.user || connection.properties?.user || …` and
  `password = connection.properties?.password || process.env.PGPASSWORD` (line ~281).
  This is the single injection point: when IAM is detected and no password is
  present, mint a token and use it as `password`.
- **Nested properties + SSL are already handled here.** `4e264e3` made the
  Postgres path read driver props from the nested `properties.properties.*` map
  and SSL from `handlers.postgre_ssl.*`, and build TLS from `sslrootcert`
  (verify-full → CA from the bundle). The IAM code **reuses** this nested-read /
  SSL-config logic rather than reinventing it.
- `src/config-parser.ts` `loadCredentials()` decrypts `credentials-config.json`
  and, when present, sets `connection.user` / `connection.properties.user` from
  `#connection.user` and `connection.properties.password` from `#connection.password`.
- Note the nested-properties caveat still matters for **detection**: DBeaver's
  driver props (incl. `awsProfile`) live at `connection.properties.properties.*`.

### Two on-disk shapes of an Aurora IAM connection
Both must be recognized.

1. **Plugin-created** (e.g. `aurora_pg_prod`, the primary target):
   - `provider: aurora-iam-postgresql`, `driver: aurora-postgresql`
   - **`url` is NOT persisted**, **`wrapperPlugins` is NOT persisted** (the plugin
     applies the `jdbc:aws-wrapper:` URL and `wrapperPlugins: iam` at runtime)
   - `configuration.host`/`port`/`database` ARE present
   - nested `properties`: `awsProfile`, `iamRegion`, `iamExpiration`, `sslrootcert`
   - routes correctly today: `driver = aurora-postgresql` → `includes('postgres')`

2. **Bootstrap-script-created** (stock provider):
   - `driver` is a GUID, `url: jdbc:aws-wrapper:postgresql://…`,
     nested `properties.wrapperPlugins: iam`, plus `awsProfile`/`iamRegion`/`sslrootcert`
   - a GUID driver does **not** match any `executeWithNativeTool` branch →
     needs a url-scheme fallback for routing (secondary; user's connections are plugin-created)

### Detection signal
The reliable fingerprint present in **both** shapes is the nested
**`properties.awsProfile`**. Stock Postgres/MySQL connections never carry it.
Detection = `connection.properties?.properties?.awsProfile` is a non-empty string.
Corroborating signals (not required): `url` starts with `jdbc:aws-wrapper:`,
`properties.wrapperPlugins` includes `iam`, `provider` starts with `aurora-iam`.

### Username
For IAM auth the token is minted *for a specific DB user*. The username is
sourced from `connection.user` (populated by `loadCredentials` from
`credentials-config.json`). Fallback order: tool/env override →
`connection.user` → error `MISSING_USERNAME`.

## Design

### Components

1. **`isAuroraIamConnection(connection)`** → `{ isIam, engine }`
   - `isIam` = nested `properties.awsProfile` present.
   - `engine` = `postgres` | `mysql`, derived from `driver` (`aurora-postgresql`
     / `aurora-mysql`), falling back to the `jdbc:aws-wrapper:<scheme>` URL.

2. **`resolveIamConnectionParams(connection)`** → resolves, from the nested props
   and top-level config:
   - `awsProfile` (required → else `PROFILE_NOT_FOUND`)
   - `region`: `iamRegion`, else parsed from the RDS hostname
     `*.<region>.rds.amazonaws.com`, else error
   - `host`, `port`, `database`, `username` (see Username above)
   - `sslRootCert` path (CA bundle) for TLS

3. **`mintIamAuthToken(params)`** — AWS SDK v3:
   - `fromIni({ profile })` from `@aws-sdk/credential-providers` (reads the SSO
     cache; auto-refreshes from a valid cached SSO token)
   - `new Signer({ hostname, port, username, region, credentials }).getAuthToken()`
     from `@aws-sdk/rds-signer` → returns the ~15-minute token (used as password)
   - Errors are run through `classifyAwsAuthError` (below).

4. **Query-path integration** (`executePostgreSQLQuery` in `workspace-client.ts`)
   - If `isAuroraIamConnection` and no usable stored password:
     mint token → use as `password`; reuse the branch's existing SSL-config logic
     to build `ssl` from `sslRootCert` (`verify-full` semantics: `ca` from the
     bundle, `rejectUnauthorized: true`).
   - If minting throws `AUTH_REQUIRED` → propagate a typed error the tool layer
     converts into a structured "auth required" result. **Never** auto-spawn a
     browser from the query path.

5. **New MCP tool `aws_sso_login`**
   - Params: `connectionId` (preferred) or `profile`.
   - Resolves the profile, then `spawn('aws', ['sso', 'login', '--profile', P])`.
     The AWS CLI opens the browser; the tool streams the verification URL/code,
     blocks until the process exits, and returns success/failure.
   - Own timeout: `DBEAVER_SSO_LOGIN_TIMEOUT` (default ~180s), independent of the
     query timeout.
   - If `aws` is not on PATH → clear `AWS_CLI_NOT_FOUND` message.

6. **`classifyAwsAuthError(err)`** → one of:
   `AUTH_REQUIRED` (SSO token expired / no cached token / reauth needed),
   `PROFILE_NOT_FOUND`, `MISSING_USERNAME`, `TOKEN_MINT_FAILED`, `AWS_CLI_NOT_FOUND`,
   `LOGIN_TIMEOUT`, else generic. Each maps to an actionable message.

### Data flow

```
query tool
  └─ resolve connection
       └─ isAuroraIamConnection?
            ├─ no  → existing native path (unchanged)
            └─ yes → resolveIamConnectionParams → mintIamAuthToken
                       ├─ success      → pg connect (password = token, ssl = CA bundle) → results
                       └─ AUTH_REQUIRED → structured "auth required" result
                                          (names connection + profile + aws_sso_login)

model sees AUTH_REQUIRED
  └─ asks user: "SSO expired for <conn> — log in or skip?"
       ├─ skip   → stop; report not run
       └─ log in → call aws_sso_login(connectionId) → browser → success → retry query
```

### Error handling
- The query path returns the typed-error message as a normal (non-throwing
  where possible) tool result for `AUTH_REQUIRED`, so a batch of MCP calls is
  not aborted by an exception.
- `aws_sso_login` reports browser-open failure, non-zero exit, and timeout
  distinctly.
- Token-mint failures unrelated to SSO (bad profile, network, no RDS perms)
  surface as `TOKEN_MINT_FAILED` with the underlying message — not `AUTH_REQUIRED`.

### Config flags (env)
- `DBEAVER_IAM_AUTH` — `true|false`, default **on** when an Aurora IAM
  connection is detected. Lets a user force-disable the path.
- `DBEAVER_SSO_LOGIN_TIMEOUT` — seconds the `aws_sso_login` tool waits (default 180).

### New dependencies
- `@aws-sdk/rds-signer`
- `@aws-sdk/credential-providers`

(AWS CLI is assumed present for the `aws sso login` step — it is part of the
existing Aurora IAM workflow; absence is handled with a clear error.)

## Testing

- **Unit**
  - `isAuroraIamConnection`: plugin shape (no url/wrapperPlugins, has awsProfile),
    bootstrap shape (url + wrapperPlugins), and negative (stock pg/mysql).
  - region-from-hostname parser (with/without `cluster-`, gov/other partitions).
  - `resolveIamConnectionParams`: missing profile, missing username, region fallback.
  - `classifyAwsAuthError` over representative SDK/CLI error shapes.
  - `mintIamAuthToken` with a mocked `Signer` + mocked `fromIni`.
  - `aws_sso_login` with mocked `child_process` (success, non-zero, timeout, ENOENT).
- **Integration (opt-in, live)**
  - Against `aurora_pg_prod`: valid cached SSO session → silent success;
    forcibly expired session → `AUTH_REQUIRED` → `aws_sso_login` → retry success.

## Open items / notes
- **Branch setup (resolved):** the auth branch `feat/mcp-aurora-iam-auth` is
  based on `feat/export-output-path` (the active dev line, on the fork remote,
  also checked out in a worktree at `/private/tmp/omnisql-output-path`). Because
  the base is unmerged, the auth PR depends on the export branch landing first.
  The stray uncommitted changes once seen on `main` were a stale copy of the
  export work and are parked in `stash@{0}` (safe to drop).
- **MySQL/IAM:** out of scope for this plan; fast-follow on the same Signer.
- Bootstrap-shape (GUID driver) routing fallback is secondary; `aurora_pg_prod`
  is plugin-created and already routes correctly.
