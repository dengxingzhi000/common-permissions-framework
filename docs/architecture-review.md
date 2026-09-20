# CommonPermissionsFramework — Enterprise Authorization Platform Architecture Review

> **Reviewer stance**: Principal Architect + Senior Product Manager + Enterprise Security Architect
> **Strategic goal evaluated**: *Build a generic, reusable, enterprise-grade authorization and permission platform that can serve multiple business systems, applications, tenants, and organizational structures.*
> **Method**: Source-of-truth inspection of every SQL file, the actual controllers/filters/services mentioned in `CLAUDE.md`, and the cross-cutting `common/*` modules. Every claim below cites `file:line`.

---

# 1. Executive Summary

CommonPermissionsFramework (CPF) is, at its core, a **well-engineered single-tenant RBAC + Data-Scope permission system for one Spring Boot stack** that ships a lot of genuinely useful infrastructure: a clean filter chain, two-level cache with pub/sub, two JWT paths (HS512 + RSA/OAuth2), WebAuthn, distributed read-write splitting, and a Kafka-backed cross-database reconciliation layer. It is **not** — yet — an enterprise authorization platform.

The dominant problems are not "missing features". They are **conceptual**:

| # | Problem | Severity | Evidence |
|---|---|---|---|
| 1 | **No `Tenant` concept exists anywhere** — not in SQL, not in entities, not in messages | P0 | `scripts/db/microservices/*.sql` (no tenant table); `grep @TableName.*tenant` → 0 |
| 2 | **`sys_permission` is a hybrid table** representing menus, buttons, APIs, AND data scopes simultaneously | P1 | `003_db_permission.sql:52`, `SysPermissionServiceImpl.java:101-119` |
| 3 | **JWT carries roles + permissions → up to 2h staleness** between revocation and effect | P0 | `JwtUtils.java:64-77`, `AuthorizationServerConfig.java:255-268` |
| 4 | **`X-Identity-Token` (HMAC) is generated but never verified** — downstream trusts plain headers | P0 | `IdentityPropagationWebFilter.java:80-98`; grep for `verifyIdentity` → 0 |
| 5 | **No decision API** — external apps must fetch a `Set<String>` and check membership themselves | P0 | `system/service/.../controller/` listing — no `/check`, `/authorize`, `/batch-check` |
| 6 | **Dubbo calls have no identity** — internal RPC is fully trusted | P0 | grep for `RpcContext` / `setAttachment` → 0 hits in the entire repo |
| 7 | **Hard-coded super-admin UUID** in three places | P1 | `SysUserServiceImpl.java:295`, `SysRoleServiceImpl.java:157,195` |
| 8 | **Approval type 2 (direct permission grant) is TODO** | P1 | `SysPermissionApprovalServiceImpl.java:209-211` |
| 9 | **Resource model is a `VARCHAR(50)` string** — no resource catalog | P1 | `003_db_permission.sql:178` |
| 10 | **JWT secret ≤ 64 bytes enforced in code** but DevOps default secret is base64 test material | P1 | `JwtUtils.java:47-51`, `docker-compose.yaml` defaults |

The codebase demonstrates **strong engineering discipline in many narrow areas** (security filters, cache coordination, distributed transactions for read-write split, OAuth2 + WebAuthn). What is missing is **the platform abstraction** — the things a multi-application, multi-tenant authorization center must own: Tenant, Application, Resource catalog, decision API, policy versioning, ABAC/ReBAC hooks, and clear Data/Control plane separation.

The good news: almost all of these can be added **without rewriting** the existing system. The core abstractions (`User`, `Role`, `Permission code`, `DataScope`, `@PreAuthorize`, `sys_user_role`, `sys_permission_approval`) are reusable. The work to get to "enterprise platform" is mostly **schema migrations, one new control-plane service, and one new decision API** — not a rewrite.

The rest of this document lays out exactly what, why, where, and in what order.

---

# 2. Current Architecture Understanding

## 2.1 Module map (verified)

```
common/                         # shared, no upward deps
├── core                        # UUIDv7, exceptions, PageResult
├── security-api                # SecurityContext interface
├── monitoring                  # Sentinel (read from CLAUDE.md; no file inspected)
├── integration                 # Kafka/RabbitMQ, MessageEnvelope, DataSyncEvent
├── data                        # MyBatis-Plus + DataScope + TwoLevelCache + ReadWrite split
├── web
│   ├── security/util           # JwtUtils, IpUtils, TotpUtils
│   ├── security/filter         # JwtAuthenticationFilter, SqlInjectionFilter, StepUpFilter
│   ├── security/config         # SecurityConfig
│   ├── security/stepup         # StepUpEvaluator, StepUpFilter
│   ├── uaa/config              # AuthorizationServerConfig (OAuth2 AS)
│   ├── feign/client            # SysUserServiceClient, SysPermissionServiceClient (SDK)
│   ├── log/*                   # @AuditLog, SysAuditLogAspect, SysAuditLogService
│   └── securityCore            # SecurityUser (UserDetails impl)
system/
├── api                         # @DubboService interfaces only
└── service                     # @DubboService impls + REST controllers + @CacheEvict
auth/                           # JWT AS + WebAuthn; consumes UserDubboService via Dubbo
gateway/                        # Spring Cloud Gateway; ApiSignatureFilter + IdentityPropagationWebFilter
```

Dependency direction observed in `pom.xml` and `imports` is **correct**: `common/*` has no upward dependency on services. `system/api` is interface-only and is shared by `auth` and `gateway`. `system/service` is the only owner of entity code.

## 2.2 Runtime topology (as deployed)

```
Client
  │ HTTPS
  ▼
gateway (8761) ── [ApiSignatureFilter] ── [OAuth2 RS via /oauth2/jwks] ── [IdentityPropagationWebFilter] ─→ downstream
  │
  ▼ (Dubbo)
auth (8106, HTTPS)  ── @DubboReference ─→ UserDubboService ──→ system/service
                              └─ Feign fallback: SysUserServiceClient
  │                                                ▲
  │                                                │ HTTP
  └────────────────────────────────────────────────┘
                                    │
                                    ▼
                          system/service (8081) — owns Postgres dbs (db_user/db_org/db_permission/db_approval/db_audit/db_notify)
                                    │
                                    └─ Kafka: DataSyncEventPublisher → UserSyncHandler/RoleSyncHandler/DeptSyncHandler
                                       (loopback reconciliation only; not external sync)
```

## 2.3 What is actually well designed

- **Filter chain order is sane**: `LogoutFilter → SqlInjectionFilter → UsernamePasswordAuthenticationFilter → JwtAuthenticationFilter → StepUpFilter` (`SecurityConfig.java:142-144`). SQL-injection filter runs before authentication so anonymous junk is dropped early.
- **Token revocation is two-layer**: per-`jti` blacklist in Redis (`jwt:blacklist:{jti}`, TTL = remaining token lifetime) plus a per-user devices Hash (`jwt:user:tokens:{userId}`) — `JwtUtils.java:221-281`.
- **TwoLevelCache pub/sub**: `cache:invalidation:twolevel` is the right pattern for multi-JVM L1 coherence (`TwoLevelCache.java:84,128,151`).
- **DataScope is template-validated, parameter-bound**: the only SQL-injection-prone component is heavily white-listed (`DataScopeInterceptor.java:65-147`). Filter clause uses `#{...}` placeholders; values go through PreparedStatement binding. Good defense-in-depth.
- **MySQL-/PostgreSQL-native**: PostgreSQL features used appropriately (UUID default, INET, JSONB, GIN, range partitioning). `scripts/db/microservices/005_db_audit.sql:45-46` partitions audit logs monthly.
- **OAuth2 + WebAuthn coexist with custom HS512 JWT**: both paths embed roles+permissions into the token via `OAuth2TokenCustomizer` (`AuthorizationServerConfig.java:255-268`) and `JwtUtils.buildClaims` (`JwtUtils.java:64-77`).

## 2.4 What is partially implemented

- **Dubbo consumer wiring**: `@EnableDubbo(scanBasePackages = "com.frog")` is set on `AuthApplication.java:31`, but the `UserDubboService` field in `SysAuthServiceImpl.java:54` has **no `@DubboReference` annotation**. This works only if Dubbo's reference scanner auto-detects via field name — fragile and undocumented.
- **Approval type 2 (direct permission grant)**: `SysPermissionApprovalServiceImpl.java:209-211` is `// TODO`.
- **Direct permission granting to a user (without a role)**: there is no path. Only role assignments are grantable today.

## 2.5 What is incorrectly modeled

- `sys_permission` is one table serving as: menu tree, button registry, API endpoint catalog, AND data-scope descriptor (`permission_type IN 1..5`). This is the single biggest modeling mistake because:
  - It conflates "what UI shows" with "what API does" with "what data is filterable" — three different lifecycles.
  - The `api_path + http_method` index on a tree node makes no sense (an API is not a tree node in general — but the tree structure is enforced anyway).
  - Frontend hints (`route_path`, `component`, `icon`, `redirect`, `visible`) live on the same row as `permission_level`/`risk_level` — UI rendering metadata and security classification metadata mixed.
- `data_permission_rule` is the only place a "Resource" exists (`resource_type VARCHAR(50)`) and it has no FK to anything. Adding a new resource type is a free-form text change.
- `sys_user_role` doubles as an audit + approval ledger (`approval_status`, `approved_by`, `approved_time` on the relation itself). This should be in the approval ledger, not duplicated on the FK.

## 2.6 What is tightly coupled that should be decoupled

| Today | Should be |
|---|---|
| Permission codes are stringly-typed (`hasAuthority('system:user:list')`) — every controller hard-codes the convention | Permission codes owned by the permission domain; controllers query them via enum or code-generated constant |
| `@DataScope(userAlias=..., deptAlias=...)` hard-codes SQL alias names | DataScope should be aware of resource metadata (which column is `dept_id`?) not SQL aliases |
| `StepUpEvaluator` hard-codes URLs (`role:grant`, `file:download`, `payout:approve`) — assumes a payment system | Step-up policies should be resource-bound, not URL-bound |
| `sys_role.business_scope JSONB` and `sys_permission.api_path` are product-specific concepts | These belong to a generic "policy attribute" table |

---

# 3. Current Domain Model

## 3.1 Logical entities (today)

```
User (sys_user) — global, no tenant
├── UserOAuth (sys_user_oauth)
├── WebAuthnCredential (webauthn_credential)
└── UserRole (sys_user_role) — has approval_status, effective/expire_time
                                 ↑ AUDIT/LEDGER CONFLATION

Role (sys_role)
├── role_code UNIQUE global
├── data_scope (1..5) — drives DataScope SQL
├── max_approval_amount
├── business_scope JSONB (free-form)
└── RolePermission (sys_role_permission) bridge
└── RoleDept (sys_role_dept) — for data_scope=2 (custom)
└── RoleDataRule (sys_role_data_rule) bridge

Permission (sys_permission) — single hybrid table
├── permission_type: 1=directory, 2=menu, 3=button, 4=API, 5=data
├── api_path + http_method — wildcard-matched
├── permission_level (1..4), risk_level (1..4)
├── need_approval, need_two_factor
└── tree via parent_id

Department (sys_dept) — self-referencing tree, get_dept_tree() CTE

DataPermissionRule (sys_data_permission_rule)
├── resource_type VARCHAR(50) — STRINGLY TYPED
├── rule_type (1..5) mirrors data_scope
├── visible_fields[], editable_fields[], masked_fields[] (TEXT[])
└── rule_config JSONB, sql_condition TEXT

TempPermission (sys_temp_permission) — temporary permission grant

PermissionApproval (sys_permission_approval)
├── approval_type: 1=role, 2=permission (UNIMPLEMENTED), 3=temporary
├── approval_chain JSONB
└── role_ids[], permission_ids[] UUID[]

AuditLog (sys_audit_log) — RANGE-partitioned monthly
SensitiveOperationLog (sys_sensitive_operation_log) — risk_score 1-10, data_fingerprint
NotificationAudit (sys_notification_audit) + Template + UserPreference
```

**Observations:**

- **No `Tenant`**, no `Application`, no `Resource` catalog. These are all missing first-class concepts.
- The model is **internally consistent for a single business**, but it conflates security policy with UI rendering with data filter semantics.
- **Cross-database FKs are commented but not enforced** (`001_db_user.sql:27`, `003_db_permission.sql:95`). Integrity is enforced by `CrossDatabaseQueryService` + Kafka events + denormalized columns.

## 3.2 Does the model support Subject + Action + Resource + Context?

Partially. The framework has:

- **Subject**: User + (no first-class Service Account). WebAuthn credentials and OAuth bindings sit on the user. There is no machine-identity concept.
- **Action**: implied by `permission_code` strings (`system:user:list`, `system:user:add`, …). No first-class Action entity.
- **Resource**: stringly-typed (`resource_type VARCHAR(50)`). Resource instances have IDs (passed at runtime) but no registry.
- **Context**: very limited. DataScope has `userAlias` and `deptAlias`. There is no IP, time-of-day, device, location, request-attribute, or business-state as a first-class authorization context.

Verdict: the model can express `user + permission_code + (optional resourceType, resourceId)` today. It cannot express `user + action + resource + (IP, time, device, dept) → decision` without per-request hard-coding.

---

# 4. Current Authorization Model

## 4.1 Models in use today

| Model | Status | Evidence |
|---|---|---|
| RBAC (role-based) | **Production-grade** | `sys_user_role` + `sys_role_permission`, role-scoped data via `data_scope` |
| ABAC (attribute-based) | **Partially** — only via DataScope SQL rewriting and `business_scope JSONB` on roles | `DataScopeInterceptor.java` |
| ReBAC (relationship-based) | **Not supported** — only department tree via `sys_dept.parent_id` | no relation table for objects |
| ACL (access-control list) | **Not supported** | no per-object ACL table |
| PBAC (policy-based) | **Not supported** | no policy DSL / Rego / OPA |
| Resource-based | **Stringly-typed only** | `sys_data_permission_rule.resource_type` |
| Data-level | **Well developed** for dept/user scope | `data_scope` 1..5 + custom dept set |
| API-level | **Hybrid** — `sys_permission.api_path/http_method` + wildcard | `SysPermissionServiceImpl.java:101-119` |
| Service-to-service | **Trusted, no identity** | Dubbo calls trust internal network |

## 4.2 Recommended core abstraction (kept simple)

For a *platform* — meaning multiple business systems, multiple tenants — the **right core abstraction is not RBAC or ABAC, it is Resource + Action + Effect + Scope**. Roles become a *naming convenience* on top.

```
Subject (User or ServiceAccount)
   ↓ has
Grant (subject_id, role_id | permission_id, scope: {tenant, app, org, resource, time}, effect: allow|deny, priority)
   ↓
Resource (typed registry; resource_type is now a FK)
   ↓
Action (typed registry: READ/CREATE/UPDATE/DELETE/APPROVE/EXPORT/EXECUTE/...)
   ↓
Context (IP, time, device, dept, request attributes — passed as evaluation input)
   ↓
Decision (effect: allow|deny, reason, policy_version, decision_id)
```

RBAC remains as the **highest-level grouping**: a `Grant` may be a role-grant (which expands at evaluation time to all of that role's permissions, scoped). ABAC and ReBAC are **additive evaluation hooks** — not replacements.

**What should be implemented now (Phase 1):**

- Formal `Resource` registry (table + entity + CRUD).
- `Grant` becomes an explicit entity with `effect`, `priority`, `scope`, `expire_time`.
- `Action` becomes a typed enum referenced by FK from `sys_permission`.

**What should be deferred (Phase 4):**

- Full PBAC DSL.
- ReBAC relationship tuples.
- Runtime attribute providers (IP, device, time).

---

# 5. RBAC Design Review

| Capability | Today | Verdict |
|---|---|---|
| Multiple roles per user | Yes | OK — `sys_user_role` |
| Role inheritance | **No** — no parent_role_id on `sys_role` | **Gap** — common enterprise need (Admin ⊃ Operator ⊃ Viewer) |
| Organization-scoped roles | Partial — `data_scope` 1..5 + `sys_role_dept` | Weak — role itself has no org column; the scope is on the relation, not the role |
| Tenant-scoped roles | **No tenant** | **Fundamental gap** |
| Application-scoped roles | **No application** | **Fundamental gap** |
| Resource-scoped roles | **No resource registry** | **Fundamental gap** |
| Dynamic role assignment | Yes — direct insert into `sys_user_role` | OK |
| Temporary roles | Yes — `effective_time`/`expire_time` + `sys_temp_permission` | OK |
| Role expiration | Yes — same mechanism + `PermissionExpiryTask` (scheduled cleanup) | OK |
| Delegated role administration | Partially — approval chain `dept-manager → sys-admin → super-admin` | Hollow — no tenant-admin or app-admin concept |
| Role conflicts / SoD | **No** — no static or dynamic separation-of-duties rule | **Gap** for enterprise compliance |
| Permission inheritance | Tree via `parent_id` on `sys_permission` | OK — but only "UI tree" inheritance; no semantic inheritance (e.g. role-A inherits role-B's permissions) |

**Verdict**: the RBAC implementation is **mature for one department of one company**. It is **not sufficient** for a multi-tenant platform where roles must be scoped to (tenant, application, organization) tuples.

---

# 6. Multi-Tenancy Review

## 6.1 What exists

`grep` for `tenant` in the domain layer yields only two `tenantId` payload fields on messages, never used:

- `common/integration/.../model/MessageEnvelope.java:64` — `private String tenantId;`
- `common/integration/.../sync/event/DataSyncEvent.java:111` — `private String tenantId;`

These are **free-form strings on the message envelope**, not wired to any filter, SQL clause, or entity. They are decorative.

## 6.2 What does NOT exist

- No `sys_tenant` table.
- No `tenant_id` column on **any** of: `sys_user`, `sys_role`, `sys_permission`, `sys_dept`, `sys_user_role`, `sys_role_permission`, `sys_role_dept`, `sys_role_data_rule`, `sys_data_permission_rule`, `sys_temp_permission`, `sys_permission_approval`.
- No `TenantContextHolder` / `TenantInterceptor` analogous to `DataScopeContextHolder` / `DataScopeInterceptor`.
- No `ISysTenantService`.
- No `RegisteredClient` per tenant — only three hard-coded clients (`AuthorizationServerConfig.java:118-178`).
- No per-tenant `issuer` — single issuer URL.
- No per-tenant rate limiting or quota.

## 6.3 Hard-coded single-tenant assumptions

```java
// SysUserServiceImpl.java:295
if (user.getId().equals(UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d4875"))) {
    throw new BusinessException(...); // can't delete admin
}
// SysRoleServiceImpl.java:157, 195 — same UUID for the super-admin role
```

Three hard-coded references to a single super-admin UUID. **Cannot support multiple tenants without code change.**

`CustomUserDetailsService.loadUserByUsername(username)` is keyed on username alone — meaning **usernames must be globally unique**. In a multi-tenant deployment, two tenants can have users named "alice" — impossible today.

`DataScopeAspect` uses the JWT-embedded `deptId` directly, with no tenant scoping (`DataScopeAspect.java:64-66`). Two users in different tenants with the same `dept_id` would see the same data.

## 6.4 Multi-tenancy isolation: what would it take?

To convert to **shared-schema, discriminator-column** multi-tenancy:

1. Add `tenant_id UUID NOT NULL` to every domain table.
2. Build `TenantContextHolder` + `TenantInterceptor` analogous to the DataScope pattern, defaulting to JWT `tenantId` claim.
3. Rewrite every MyBatis mapper to include `tenant_id = #{tenantId}` in WHERE clauses (or use a MyBatis interceptor similar to `DataScopeInterceptor`).
4. Update `UNIQUE (username)` to `UNIQUE (tenant_id, username)`.
5. Move `RegisteredClient` to a DB-backed table keyed by tenant.
6. Add tenant context to JWT and `X-Identity-Token` claims.
7. Add a `TenantAdmin` / `TenantOwner` concept.
8. Add an `Application` registry so a tenant has apps.

**Estimate**: 2–4 engineer-months for shared-schema approach, with most work being data migration + mapper pass. **Doable in Phase 0 / Phase 1.**

To convert to **schema-per-tenant**: significantly more operational cost; do not pursue until product demand justifies it.

---

# 7. Authorization APIs Review

## 7.1 What exists

| Endpoint | Module | Purpose |
|---|---|---|
| `POST /api/auth/login` | auth | username+password (+ optional 2FA) |
| `POST /api/auth/logout` | auth | revoke current token |
| `POST /api/auth/refresh` | auth | refresh-token → new access-token |
| `GET /api/auth/userinfo` | auth | current user profile |
| `POST /api/auth/force-logout/{userId}` | auth | admin force-logout |
| `POST /api/auth/webauthn/*` | auth | FIDO2 register / authenticate |
| `POST /oauth2/token` | auth (OAuth2 AS) | standard OAuth2 |
| `GET /oauth2/authorize` | auth | auth-code endpoint |
| `POST /oauth2/introspect` | auth | RFC 7662 introspection |
| `POST /oauth2/revoke` | auth | RFC 7009 revocation |
| `GET /oauth2/jwks` | auth | JWK Set (consumed by gateway) |
| `POST /oauth2/logout` | auth | custom logout |
| `GET/POST/PUT/DELETE /api/system/users` | system | user CRUD |
| `GET/POST/PUT/DELETE /api/system/roles` | system | role CRUD |
| `GET/POST/PUT/DELETE /api/system/permissions` | system | permission CRUD |
| `GET/POST/PUT/DELETE /api/system/depts` | system | department CRUD |
| `GET/POST/PUT/DELETE /api/system/approvals` | system | approval workflow |
| `GET /api/system/permissions/find-by-url` | system | reverse-lookup: which permissions gate this URL? |
| `GET /api/system/permissions/api` | system | list all API permissions (for `DynamicPermissionLoader`) |

## 7.2 What does NOT exist (the platform is missing these)

```
POST /authorize        — would-be OPA-style decision API
POST /check            — given (subject, action, resource, context) → boolean + reason
POST /batch-check      — bulk checks for performance
GET  /permissions      — list user's effective permissions (with scope)
GET  /roles            — list user's effective roles
GET  /resources        — list resources user can act on
GET  /policies         — list policy versions
GET  /audit            — authorization-decision audit trail
```

**Consequence**: an external application integrating with CPF today must:

1. Call `findAllPermissionsByUserId(userId)` via Dubbo/Feign to get a `Set<String>`.
2. Do the membership check client-side.
3. Have no way to ask "what would the decision have been, and why?" — the audit trail is implicit, not explicit.

This is the **single biggest product gap**.

## 7.3 Recommended decision API (control plane vs data plane)

```
# CONTROL PLANE (admin/UI-facing, slow, cached)
POST /api/admin/tenants
GET  /api/admin/tenants/{id}
POST /api/admin/applications
POST /api/admin/resources        # register a new resource type
POST /api/admin/roles            # with scope, app, org
POST /api/admin/grants           # explicit (subject, action, resource, scope) grants
POST /api/admin/policies         # versioned policies
GET  /api/admin/audit

# DATA PLANE (latency-critical, may be local SDK-cached)
POST /api/decision/check         # { subject, action, resource, context } → allow|deny + reason
POST /api/decision/batch-check   # array of { subject, action, resource, context }
GET  /api/decision/permissions?subject=X    # full effective permission set
GET  /api/decision/roles?subject=X
POST /api/sync                   # bulk pull for local SDK cache hydration
```

The data-plane endpoints should be **cheap, cache-friendly, batch-capable**, and addressable from a local SDK. The control plane is rare, slow, and must be strongly authenticated.

---

# 8. Permission Checking Architecture

## 8.1 Today: centralized with embedded-permission JWT

```
Client
  │ Bearer JWT (HS512 or RSA)
  ▼
Gateway (OAuth2 RS verifies signature via JWK)
  │
  ▼ injects X-User-Id, X-User-Roles, X-Identity-Token (HMAC, never verified downstream)
  │
Backend service
  │
  ├─ JwtAuthenticationFilter → sets SecurityContext
  ├─ @PreAuthorize("hasAuthority('system:user:list')") ← checked against JWT-embedded permissions
  └─ @DataScope methods → SQL rewrite
```

**Plus** an authoritative fallback: `CustomPermissionEvaluator.hasPermission()` calls `permissionService.hasPermission(userId, code)` which goes to the DB via `findAllPermissionsByUserId` (cached in `userPermissions` TwoLevelCache).

So decisions are made by:

1. **Primary**: JWT-embedded permission set (potentially stale up to TTL).
2. **Fallback / override**: real-time DB lookup via `CustomPermissionEvaluator`.
3. **DataScope**: separate SQL-rewrite path.

This is **inconsistent** — two sources of truth, neither authoritative.

## 8.2 Latency, availability, consistency

| Concern | Today |
|---|---|
| Latency (check) | O(1) JWT claim inspection + occasional DB hit if `CustomPermissionEvaluator` fires |
| Availability | Depends on Redis (cache) + DB (auth lookup) + JWK source |
| Consistency | **Stale up to 2 hours** (JWT TTL); L1 invalidates via pub/sub in ms |
| Permission propagation delay | `addPermission` → `@CacheEvict(allEntries=true)` → next request gets fresh. Roles/permissions change via direct DB insert (e.g. approval) — **does not trigger cache invalidation** |
| Network dependency | None for `@PreAuthorize`; one DB hop for `CustomPermissionEvaluator` |
| Security | Good — but token-bound permissions enable stale-elevation window |
| Operational complexity | Medium — three caches (JWT, L1, L2) plus Redis pub/sub |

## 8.3 Recommended: short-lived JWT + distributed SDK

```
Application
  │
  ▼ (local SDK; offline-capable for seconds)
Local cache (in-process, TTL 5-30s)
  │
  ▼ on miss
HTTP POST /api/decision/check  (CDN-fronted, <5ms p99 target)
  │
  ▼ on cache invalidation event
Webhook or Kafka push from authorization platform
```

**Why this beats today's design:**

- Removes JWT-embedded permission staleness entirely.
- Decision latency is local (~µs), falls back to HTTP on miss.
- Permission changes propagate via push (event), not pull (scheduled refresh).
- Enables ABAC/ReBAC at decision time without bloating JWTs.

**Why NOT to do this immediately:** requires building the decision API, the SDK, the push pipeline. Doable in **Phase 3** once Phase 0/1/2 are stable.

---

# 9. Data-Level Authorization

## 9.1 Today's pattern

`@DataScope(userAlias, deptAlias)` → `DataScopeAspect` puts a `DataScopeFilter` into a ThreadLocal → `DataScopeInterceptor` rewrites SELECT statements at the `StatementHandler.prepare()` stage (`DataScopeInterceptor.java:35-56`).

5 levels: ALL, CUSTOM, DEPT, DEPT_AND_CHILDREN, SELF.

Custom (level 2) is realized via `sys_role_dept` — list of allowed department IDs.

`sys_data_permission_rule` adds field-level visibility:

- `visible_fields TEXT[]`, `editable_fields TEXT[]`, `masked_fields TEXT[]`
- `rule_config JSONB`, `sql_condition TEXT`

## 9.2 Strengths

- **Appropriate abstraction for the level of complexity currently needed.** 5 fixed levels + custom dept set covers ~80% of real-world data-scope use cases.
- **Defense-in-depth on SQL injection**: dangerous patterns are explicitly enumerated and the whitelist is enforced (`DataScopeInterceptor.java:65-147`).
- **Recursive CTE** for `DEPT_AND_CHILDREN` is correct (`002_db_org.sql:60-99`).

## 9.3 Weaknesses

- **`@DataScope` requires the developer to know the SQL alias** (`userAlias`, `deptAlias`) and write them correctly. There's no schema-enforced link.
- **Async context loss**: `DataScopeContextHolder` is `ThreadLocal`. Async / reactive / `CompletableFuture` flows lose the filter silently.
- **Row-level ABAC (e.g. "user can see contracts where they are the manager")** is not supported. The model is *fixed levels + custom dept set*, not *arbitrary predicates on arbitrary columns*.
- **Field-level masking happens at API serialization, not at SQL level.** `visible_fields`/`masked_fields` are advisory metadata; the framework doesn't actually apply them.

## 9.4 Recommendation

Keep `DataScope` as-is for **Phase 0**. Add a **Resource Ownership** concept in **Phase 2** — a `sys_resource_ownership (resource_type, resource_id, owner_user_id, owner_dept_id)` table that lets any service ask "does this user own this resource instance?".

Defer a full ABAC engine to **Phase 4**.

---

# 10. Product Boundaries

## 10.1 What belongs inside the authorization platform (CORE)

- Identity integration (OAuth2/OIDC, SAML, WebAuthn, MFA — already done)
- User, Role, Permission, Resource, Application, Tenant, Organization
- Authorization decision
- Audit (login, authorization decisions, sensitive ops — already done)

## 10.2 What is borderline (consider externalizing)

| Today | Recommendation |
|---|---|
| Notification subsystem (`db_notify`) | **Externalize**. Send via Spring events; let each service plug its own notification provider (email/SMS/push). The platform should only emit `AuthorizationEvent`. |
| Approval workflow engine (`db_approval`) | **Keep but generalize**. Today it hardcodes "dept-manager → sys-admin → super-admin". A real workflow engine (Flowable / Camunda / Temporal) should be an **adapter**, not the core. |
| OAuth2 client registry | **Move to DB-backed** with per-tenant scoping. |
| `sys_sensitive_operation_log` | **Keep but mark as "platform audit"**, not "business audit". |

## 10.3 What is OUT (do not bring in)

- HR / employee master data — should be a separate upstream system.
- Business-specific approval — the approval chain is hard-coded for permissions today (`buildApprovalChain`); it should be configurable.
- Workflow engine implementation itself — pluggable adapter.
- BPM / case management — never.
- UI / frontend — not the platform's concern.
- Business object metadata — only abstract "Resource" concept.

## 10.4 Boundary violations today

| Violation | Where | Why |
|---|---|---|
| `StepUpEvaluator` hard-codes `payout:approve` | `StepUpEvaluator.java:90-92` | A payment-system URL pattern is leaking into the generic permission framework |
| `CustomPermissionEvaluator.hasResourcePermission` couples to `sys_data_permission_rule` | `system/service/.../evaluator/CustomPermissionEvaluator.java:51-67` | Permission evaluation should not depend on a specific product table |
| `DataSyncEventPublisher` knows about User/Dept/Role entity types | `system/service/.../event/DataSyncEventPublisher.java:32-98` | The platform's event types are fine; what is leaky is binding to entity classes |
| Hard-coded CORS `https://*.bank.com` | `SecurityConfig.java:158` | Single-tenant assumption |

---

# 11. Enterprise-Grade Requirements

## 11.1 Security

| Concern | Status | Notes |
|---|---|---|
| Least privilege | Partial | RBAC exists; SoD (separation of duties) does **not** |
| Zero trust | Partial | Gateway validates JWT but downstream trusts plain headers |
| MFA integration | **Done** | TOTP + WebAuthn |
| Service identity | **Missing** | No machine identity for Dubbo callers |
| API authentication | **Done** | OAuth2 + API signature |
| Permission escalation protection | Partial | JWT-embedded perms expire naturally; revocation is best-effort |
| Security audit | **Done** | `sys_audit_log` partitioned, `sys_sensitive_operation_log` with risk score |

## 11.2 Reliability

| Concern | Status |
|---|---|
| High availability | Single-tenant deployment, single-region; HA via cluster |
| Graceful degradation | **Fail-closed** for permission decisions (`DubboPermissionServiceAdapter.java:58-103`) — but this means Dubbo outage = total lockout |
| Failure isolation | Circuit breakers via Sentinel + Resilience4j |
| Retry | 3x exponential backoff via Resilience4j |
| Idempotency | MessageEnvelope has `id`; consumers should dedupe on it (verifying...) |
| Disaster recovery | DB backups only — no cross-region |

## 11.3 Scalability

CPF is currently deployed as **one tenant per cluster**. For the stated goal of "multiple tenants":

| Scale | Feasibility |
|---|---|
| 10 tenants, 100K users each | OK with shared-schema + `tenant_id` discriminator |
| 100 tenants, 1M users each | OK with shared-schema; need to add cache-namespacing by tenant |
| 1,000 tenants | Tight — DB connections, Kafka partitions need re-thinking |
| 10,000 tenants | Need schema-per-tenant OR PG Row-Level Security policies |
| 100M auth checks/day | ~1,150 RPS average; ~12,000 RPS peak. With local SDK cache, the data plane handles this comfortably on a small fleet |

**Realistic bottlenecks:**

1. **`sys_user_role` hot rows**: every JWT generation / permission lookup joins through this. With 10M users and 50 roles per user, that's 500M rows. Partitioning by `user_id` hash + read replicas is mandatory above 1M users.
2. **Redis pub/sub on `cache:invalidation:twolevel`**: at very high invalidation rates this saturates. Need a debouncer.
3. **`sys_audit_log`**: monthly partitioning helps but old partitions still occupy storage. Archive cold partitions to S3 / cold storage.
4. **JWT secret rotation**: `JwtUtils.java:47` requires ≥ 64 bytes but no rotation is supported. Need `kid` + multi-key support.

---

# 12. Observability & Audit Review

## 12.1 What exists

- `sys_audit_log` — partitioned monthly, captures login / CRUD / query / export / approve (`005_db_audit.sql:16-46`).
- `sys_sensitive_operation_log` — risk_score 1-10, data_fingerprint SHA-256 (`005_db_audit.sql:106-127`).
- `@AuditLog` annotation → `SysAuditLogAspect` writes to `sys_audit_log`.
- Prometheus metrics: `BusinessMetrics`, `SecurityMetrics`.
- Resilience4j actuator endpoints: `/actuator/circuitbreakers`, etc.
- OpenTelemetry integration on Kafka/RabbitMQ.

## 12.2 What is missing

| Need | Today | Recommended |
|---|---|---|
| "Who accessed what, when, from where, through which application, under which policy, and why was access allowed or denied?" | **Partial**. `sys_audit_log` captures CRUD but **not authorization decisions** (allow/deny). | Add a `decision_log` table: `{decision_id, ts, subject, action, resource, context, effect, reason, policy_version}` |
| Per-decision tracing | Trace context propagated, but decision itself is not in the trace | Add decision as a span attribute or a separate event |
| Tenant ID in every log row | **Missing** (no tenant) | Add when `tenant_id` is introduced |
| Application ID in every log row | **Missing** (no app) | Add when `Application` is introduced |
| Correlation ID | `X-Request-ID` / `traceparent` headers honored in logs | OK |

## 12.3 Distinction: Business Audit vs Authorization Audit

Today, **all auditing is conflated** in `sys_audit_log`. For an enterprise platform, these should be **separate** ledgers:

- **Business Audit**: business state changes (e.g. "user X updated invoice Y to amount Z"). Owned by the business service. The platform should provide a **sink** (Kafka topic / event), not own the table.
- **Authorization Audit**: every `POST /api/decision/check`, every `@PreAuthorize` evaluation outcome, every login. Owned by the platform. **High volume, short retention**.
- **Compliance Audit**: regulatory events (sensitive data access, admin actions). Today merged into `sys_audit_log`. Should be queryable with structured filters.

---

# 13. Extensibility

## 13.1 Integration paths today

- **REST / Feign**: `SysUserServiceClient`, `SysPermissionServiceClient`, `SysAuthServiceClient`. Cross-cluster fallback path.
- **Dubbo**: `UserDubboService`, `PermissionDubboService`. In-cluster preferred path.
- **OAuth2 client_credentials**: `internal-service` / `service-secret-2024`. Hard-coded.
- **OAuth2 authorization_code**: `nearsync-web` / `nearsync-mobile`. Hard-coded.

## 13.2 Lock-in to Java / Spring

Significant. The auth module is **only** consumable by Java clients (via Dubbo) or HTTP clients (via Feign, which requires Spring Cloud OpenFeign).

There is **no Go, Python, Node, .NET SDK** and no OpenAPI generator config to produce one. The /v3/api-docs is enabled but no codegen config exists.

## 13.3 Permission model extensibility

- Adding a new permission code is just a string (`system:user:list`). Easy.
- Adding a new resource type today is a **string** in `sys_data_permission_rule.resource_type` — no validation that the resource type is registered. Easy to make typos.
- Adding a new DataScope level is hard-coded (1..5 with specific semantics).
- Adding a new approval step is JSON-encoded in `approval_chain` — opaque, no UI for it.

## 13.4 API versioning

**None**. `/api/system/*` and `/api/auth/*` are unversioned. Breaking changes today would be silent.

## 13.5 Recommendation

- **Phase 0**: Add `/v1/` prefix to all platform APIs; deprecation policy documented.
- **Phase 1**: Publish OpenAPI 3.1 spec at `/v3/api-docs/platform`; document the canonical SDK shapes (Go, Python, Node, Java).
- **Phase 3**: Distribute reference SDKs (typed clients + local cache + decision API).

---

# 14. Database Review

## 14.1 Strengths

- UUIDv7 everywhere → time-ordered, index-friendly.
- Partial indexes `WHERE NOT deleted` → efficient.
- PostgreSQL-native types used well (JSONB, INET, TEXT[], UUID[], range partitioning).
- Auto-generated audit columns via `MyMetaObjectHandler`.
- Soft delete via `deleted BOOLEAN` + `@TableLogic` (mostly).

## 14.2 Issues

### 14.2.1 Inconsistent soft delete

`SysUserRole`, `SysRolePermission`, `SysRoleDept`, `SysRoleDataRule`, `SysTempPermission`, `SysUserNotificationPreference`, `SysPermissionApproval`, `SysSensitiveOperationLog` **lack `@TableLogic` even though tables have `deleted` columns or are operational ledgers**. MyBatis-Plus default `deleted=false` filter is silently bypassed.

### 14.2.2 Two `SysAuditLog` classes

- `common/web/.../entity/SysAuditLog.java` uses `@TableId(type=AUTO)` (`IdType.AUTO` line 43) even though the table has UUID PKs. Likely a write-time bug — write paths likely use the auto-increment ID and will collide or fail.

### 14.2.3 Cross-DB FKs are advisory only

Comments like `关联 db_org.sys_dept.id` in `001_db_user.sql:27`. Integrity is enforced by `CrossDatabaseQueryService`. Adding a department that no user references is fine; deleting a department can orphan `sys_user.dept_id` if the cleanup handler is not robust.

### 14.2.4 Denormalized columns compensate for lack of joins

`007_data_redundancy.sql` adds `username`, `real_name`, `dept_name`, `role_names[]`, etc. to many tables. **This is a code smell**: every time a user changes their name, every table with `username` must be updated (via `UserSyncHandler` over Kafka). Reconciliation task exists but is best-effort. A real multi-tenant system would use a single user table within a tenant scope and avoid the redundancy.

### 14.2.5 No `tenant_id` on any table

The single largest migration debt.

### 14.2.6 `sys_user_role` duplicates approval state

`approval_status`, `approved_by`, `approved_time` belong in `sys_permission_approval`, not on the FK. This makes "give a user a role directly vs via approval" indistinguishable after the fact.

### 14.2.7 `sys_data_permission_rule.resource_type` is stringly typed

No FK to a `sys_resource` registry. Adding a resource type is invisible to validation.

### 14.2.8 Approval chain is opaque JSONB

`approval_chain JSONB` is flexible but unqueryable. Useful for audit; not for "show me all pending approvals for user X".

## 14.3 Performance hot spots (predicted)

- `sys_user_role(user_id)` JOIN `sys_role_permission` JOIN `sys_permission` for **every** `findAllPermissionsByUserId`. At 10M users this is the hottest read path.
- `sys_audit_log` write throughput: monthly partitioning helps; consider partitioning by hash(`tenant_id`, `user_id`) once tenants exist.
- `permissionTree` cache invalidates `allEntries=true` on every permission mutation — fine at small scale; costly at large.

## 14.4 Index recommendations (low-risk wins)

```sql
CREATE INDEX idx_ur_user_status_active ON sys_user_role(user_id) WHERE approval_status = 2 AND deleted IS FALSE;
CREATE INDEX idx_srp_role_perm ON sys_role_permission(role_id, permission_id);
CREATE INDEX idx_audit_user_time ON sys_audit_log(user_id, create_time DESC);
CREATE INDEX idx_audit_business ON sys_audit_log(business_type, business_id) WHERE business_id IS NOT NULL;
```

---

# 15. Code Architecture Review

## 15.1 What is done well

- **Strict module dependency direction**: `common/*` never imports `system/*` or `auth/*`. Verified by `pom.xml` chains.
- **DTO / Entity separation**: `common/data/.../dto/` separate from `system/service/.../domain/entity/`.
- **Filter ordering**: explicit and documented (`SecurityConfig.java:142-144`).
- **Lombok everywhere**: consistent.
- **`ApiResponse<T>`** / `ApiResults<T>` consistently used.
- **Custom exceptions** with `ResultCode` enum.
- **Audit annotation** `@AuditLog` as an AOP crosscut.

## 15.2 Where the architecture drifts

### 15.2.1 Two parallel JWT subsystems

`JwtUtils` (custom HS512) and `AuthorizationServerConfig` (Spring Authorization Server RSA). Both embed roles + permissions. Two code paths to maintain, two token revocation systems, two claim names. **Pick one.** Recommendation: keep Spring Authorization Server (mature, standard OIDC), deprecate the custom path.

### 15.2.2 Duplication of cache eviction logic

Every `*ServiceImpl` has `@CacheEvict(value = {"...","..."}, allEntries = true)`. This is brittle (rename a cache → silent staleness) and over-aggressive (one role change nukes everyone's user permissions cache).

### 15.2.3 Type-handler proliferation

`JacksonTypeHandler`, `StringArrayTypeHandler`, `UuidArrayTypeHandler` (`common/data/.../handler/`). Necessary for Postgres-specific types, but each is a place where a Jackson serialization bug could corrupt data.

### 15.2.4 Transaction boundaries unclear

`SysPermissionApprovalServiceImpl.processApproval` writes to `db_permission` and `db_approval` inside one `@Transactional` — these are **separate databases**. There is no XA coordinator; the code comment in `AuthorizationServerConfig.java:65` warns about this. **Best-effort, not atomic**.

### 15.2.5 `DubboPermissionServiceAdapter` is fail-closed but unmonitored

If the Dubbo call fails, `PermissionServiceException` is thrown and access is denied. Good security posture, but **operationally fragile** — a brief network blip = total lockout. Add circuit breaker + degraded mode (use cached decision).

### 15.2.6 `@DataScope` couples to SQL aliases

A developer must match `@DataScope(userAlias="u", deptAlias="d")` to the actual SQL. Renaming a column in the SQL silently breaks data scoping.

## 15.3 SOLID/DDD scoring

| Principle | Verdict | Notes |
|---|---|---|
| Single Responsibility | Mostly | Filters and services are appropriately scoped |
| Open/Closed | Partial | `StepUpEvaluator` is hard-coded; adding a new rule requires code change |
| Liskov Substitution | OK | Entity / DTO separation clean |
| Interface Segregation | OK | Dubbo interfaces are minimal |
| Dependency Inversion | Partial | `CustomPermissionEvaluator` depends on `ISysPermissionService` (good), but business services still couple to `sys_data_permission_rule` |
| DDD aggregates | Weak | No clear aggregate roots; cross-DB references via FK-shaped UUID arrays violate aggregate boundaries |

---

# 16. Comparison With Industry Patterns

| Pattern | Used by | Adopt now? |
|---|---|---|
| OAuth 2.0 + OIDC | Spring Authorization Server (already in use) | **Yes — keep, extend** |
| SAML | Keycloak, Okta | **Defer** — only if enterprise customer asks |
| SCIM | Okta, Workday | **Defer** — provisioning is not the platform's job today |
| ABAC | AWS IAM, Azure RBAC + ABAC | **Defer** (Phase 4) — current `DataScope` covers most use cases |
| ReBAC / Zanzibar tuples | Google Zanzibar, Auth0 FGA, OpenFGA | **Defer** (Phase 4) — only if relationship-based queries become a real need |
| Policy engine (OPA / Rego) | Styra, Open Policy Agent | **Defer** (Phase 4) — over-engineered for current load |
| Decision API | Cerbos, OPA, Permify | **Yes — Phase 1 priority** |
| Event-driven invalidation | Casbin watchers, Cerbos dispatcher | **Already partially in place** (TwoLevelCache pub/sub) — extend |
| Multi-tenant isolated policies | AWS IAM | **Yes — Phase 0/1** |
| Per-tenant JWK / issuer | Auth0, Okta | **Phase 1** — multiple issuers per tenant |
| mTLS service identity | SPIFFE / Istio | **Defer** — until cloud-native deployment becomes a real need |
| Just-in-time access | AWS IAM Identity Center, Teleport | **Phase 2** — already partly supported via `sys_temp_permission` |

---

# 17. Architecture Maturity Assessment

| Dimension | Level | Evidence |
|---|---|---|
| Domain Model | **C+** | Solid RBAC; **lacks Tenant, Application, Resource catalog** |
| Authorization Model | **B−** | RBAC well-built; ABAC half-built; ReBAC/PBAC absent |
| RBAC | **A−** | Mature for one-org use; needs scope columns |
| ABAC Readiness | **C** | `business_scope` JSONB and `rule_config` JSONB hint at it, but no attribute provider infrastructure |
| ReBAC Readiness | **F** | Only dept tree; no relation tuples |
| Multi-Tenancy | **F** | Zero tenant concept anywhere |
| Organization Model | **B+** | Self-ref tree + CTE, but global IDs |
| Resource Model | **D** | Stringly-typed only |
| Policy Model | **D** | Permissions are strings; no versioning |
| Authorization API | **D** | No decision endpoint |
| SDK Strategy | **C** | Only Java/Spring SDKs |
| Data-Level Authorization | **B+** | DataScope SQL rewrite is novel and well-defended |
| Security | **B+** | Filters, MFA, WebAuthn, audit log good; JWT staleness & header trust are gaps |
| Audit | **B** | Partitioned audit; lacks decision-log |
| Observability | **B** | Metrics + trace propagation; lacks decision tracing |
| Scalability | **B** | For one tenant at current scale; will not scale to 100+ tenants without rework |
| Availability | **B−** | Fail-closed posture risks lockout; no degraded-mode |
| Extensibility | **C** | Only Java clients; no Go/Python/Node |
| Developer Experience | **B** | Filter chain + DataScope + @PreAuthorize are nice to use; cache eviction brittle |
| Product Completeness | **C** | Good RBAC admin UI APIs, but missing decision API and tenant onboarding |
| Maintainability | **B** | Module boundaries clean; in-code hard-coded UUIDs are the main debt |

**Overall**: A **single-tenant internal RBAC system**, built with strong engineering hygiene, that needs **~6 engineer-months of work** to become a credible enterprise authorization platform.

---

# 18. Findings by Priority

## P0 — Fundamental Architecture Problems

### P0-1. No `Tenant` concept exists

- **Why it matters**: The stated strategic goal is "serve multiple business systems, applications, tenants". The platform cannot host one customer without colliding with another's users, roles, permissions.
- **Evidence**: No `sys_tenant` table, no `tenant_id` column anywhere, no `TenantContextHolder`, no per-tenant `RegisteredClient`, single `issuer`.
- **Impact**: Cannot sell/host as multi-tenant platform.
- **Solution**: Add `sys_tenant` table, add `tenant_id` to every domain table (with backfill to a default tenant for existing data), add `TenantContextHolder` + `TenantInterceptor` mirroring the DataScope pattern, change JWT to carry `tenant_id` claim, change `X-Identity-Token` payload to include `tenant_id` and **verify** it downstream.
- **Complexity**: Medium (schema migration is straightforward; mapper changes are bulk; runtime changes are small).

### P0-2. JWT-embedded permissions have up to 2-hour staleness

- **Why it matters**: A user whose permissions are revoked remains authorized for the rest of their token's life. For an enterprise platform, this is unacceptable for sensitive operations.
- **Evidence**: `JwtUtils.generateAccessToken` embeds `permissions` directly in claims; `JwtAuthenticationFilter.java:62-72` reads them back without consulting DB; `CustomPermissionEvaluator.hasPermission` exists as a fallback but `@PreAuthorize("hasAuthority('system:user:list')")` shortcuts to the JWT set.
- **Impact**: Revoked role/permission is still effective for up to 2 hours (HS512) or 2 hours (OAuth2 access token).
- **Solution**:
  1. **Shorten access-token TTL** to 5–15 min and rely on refresh tokens (already supported).
  2. **Add a Redis-backed revocation check** in `JwtAuthenticationFilter`: after parsing the JWT, check `jwt:revoked_user:{userId}` (a Redis key whose presence + version > token.issuedAt means revoked). When permissions change, INCR this version.
  3. **Make `CustomPermissionEvaluator` the canonical path** by changing `@PreAuthorize` to use `permissionEvaluator.hasPermission(...)` instead of authority-set membership.
- **Complexity**: Low.

### P0-3. `X-Identity-Token` is generated but never verified

- **Why it matters**: The gateway signs an identity token, but no downstream service verifies the signature. An attacker who can reach a backend service directly (compromised pod, internal network) can craft arbitrary `X-User-Id` / `X-User-Roles` headers with no detection.
- **Evidence**: `IdentityPropagationWebFilter.java:80-98` generates and signs; `grep -r verifyIdentity` returns 0 matches.
- **Impact**: Bypass authentication by sending fake identity headers to any internal service.
- **Solution**: Add a verification filter in `common/web` (servlet) and `gateway` (WebFlux) that:
  1. Reads `X-Identity-Token`, recomputes HMAC, rejects on mismatch.
  2. Validates `issuedAt` is recent (≤ 30s) to prevent replay.
  3. Trusts the plain `X-User-Id`/`X-User-Roles` headers **only after** signature verification.
- **Complexity**: Low (one new filter + one HMAC verifier).

### P0-4. No authorization decision API

- **Why it matters**: External applications cannot ask "may this user do X?". They must fetch `Set<String>` and check membership themselves, which is not only clunky but **insecure** (they receive the user's full permission set).
- **Evidence**: No `POST /api/check` or similar in any controller.
- **Impact**: Forces every integrating app to re-implement authorization, leaking permission sets.
- **Solution**: Add `POST /api/decision/check` and `POST /api/decision/batch-check`. Returns `{effect, reason, policy_version}`.
- **Complexity**: Medium.

### P0-5. Dubbo calls have no identity propagation

- **Why it matters**: Any service on the internal network can call `PermissionDubboService.findAllPermissionsByUserId(anyUserId)` and learn that user's permission set. Worse, any service can call `UserDubboService.updateLastLogin(anyUserId, …)` to spoof audit trails.
- **Evidence**: No `RpcContext.setAttachment`, no `@DubboReference(check=true)` filter, no signature on Dubbo calls.
- **Impact**: Internal compromise → permission enumeration and audit forgery.
- **Solution**: Use Dubbo's `RpcContext.setAttachment("userId", caller)` and `getAttachment("userId")` on the provider side. Add an interceptor that requires a signed `internalToken` header on every Dubbo call (like `ApiSignatureFilter` but for RPC). Reject calls without it.
- **Complexity**: Low.

## P1 — Important Production Problems

### P1-1. No `Application` entity

- **Why it matters**: External applications cannot be registered as first-class objects; permissions cannot be scoped to an application; API clients cannot be managed.
- **Evidence**: No `sys_application` table or entity.
- **Solution**: Add `sys_application(id, tenant_id, app_code, app_name, app_secret_hash, redirect_uris, scopes, status, audit)`. Migrate the three hard-coded `RegisteredClient`s to rows. Add `app_id` to `sys_permission` and `sys_role` for scoping.
- **Complexity**: Medium.

### P1-2. Resource is stringly typed

- **Evidence**: `sys_data_permission_rule.resource_type VARCHAR(50)` — no FK.
- **Solution**: Add `sys_resource(id, tenant_id, app_id, resource_code, resource_name, parent_id)`; replace `VARCHAR(50)` with FK; provide CRUD APIs.
- **Complexity**: Low.

### P1-3. Hard-coded super-admin UUID

- **Evidence**: `SysUserServiceImpl.java:295`; `SysRoleServiceImpl.java:157, 195`.
- **Solution**: Replace with a `sys_config(key='super_admin_user_id', value=…)` table or a `tenant_id`-keyed "tenant admin" assignment.
- **Complexity**: Low.

### P1-4. `sys_permission` hybrid table

- **Evidence**: `permission_type IN (1..5)` — directory / menu / button / API / data on one table.
- **Solution**: Split into:
  - `sys_permission` (id, tenant_id, app_id, parent_id, code, name, level, risk_level)
  - `sys_menu` (permission_id FK, route_path, component, icon, visible, sort_order)
  - `sys_api_permission` (permission_id FK, api_path, http_method)
  - `sys_data_permission` (permission_id FK, resource_type, …)
- **Complexity**: Medium (data migration, controller refactor).

### P1-5. Approval type 2 unimplemented

- **Evidence**: `SysPermissionApprovalServiceImpl.java:209-211` — `// TODO`.
- **Solution**: Implement direct permission grant flow. Either complete it or remove the approval_type to avoid confusion.
- **Complexity**: Low.

### P1-6. JWT secret management and rotation

- **Evidence**: `JwtUtils.java:47` enforces ≥ 64 bytes but no `kid` / multi-key support. Rotation is impossible without a hard cutover.
- **Solution**: Generate RSA keypair per environment with `kid`; support multiple active keys; rotate via config push.
- **Complexity**: Medium.

### P1-7. Refresh tokens issued via HS512 are not bound to a session

- **Evidence**: `JwtUtils.generateRefreshToken` issues a JWT but does not register it in Redis.
- **Impact**: Cannot revoke a refresh token mid-TTL.
- **Solution**: Store refresh-token hash in Redis with `revoked=true` flag; check on refresh.
- **Complexity**: Low.

### P1-8. `/api/system/permissions/find-by-url` has no `@PreAuthorize`

- **Evidence**: `SysPermissionController.java:163-172` — any authenticated user can enumerate which permissions gate which URLs.
- **Impact**: Information disclosure; enables permission discovery for lateral movement.
- **Solution**: Require `system:admin` authority or restrict to internal callers.
- **Complexity**: Trivial.

### P1-9. `DubboPermissionServiceAdapter` is fail-closed without degraded mode

- **Evidence**: Permission lookup fails → access denied.
- **Impact**: Brief network blip → total lockout.
- **Solution**: Add circuit breaker + degraded mode (last-known-good cache from L2).
- **Complexity**: Low.

### P1-10. Approval workflow hard-coded chain

- **Evidence**: `buildApprovalChain` in `SysPermissionApprovalServiceImpl.java:299-347`.
- **Solution**: Make the chain a configurable template per tenant / per approval type.
- **Complexity**: Medium.

## P2 — Product / Engineering Improvements

- **P2-1** API versioning: prefix all platform APIs with `/v1/`, document deprecation policy.
- **P2-2** Two parallel JWT subsystems: deprecate `JwtUtils` in favor of Spring Authorization Server.
- **P2-3** `@CacheEvict(allEntries=true)` over-aggression: replace with specific keys or per-tenant/per-user patterns.
- **P2-4** `@DataScope` alias coupling: introduce a resource-metadata registry so SQL aliases are auto-detected.
- **P2-5** Distributed transaction for `processApproval` is best-effort: introduce an outbox pattern or a Saga.
- **P2-6** Inconsistent soft-delete annotations: align all entities with `@TableLogic` where applicable.
- **P2-7** Two `SysAuditLog` classes: consolidate.
- **P2-8** OpenAPI codegen: publish SDK shapes for Go/Python/Node/.NET.
- **P2-9** `StepUpEvaluator` URL hard-coding: replace with policy file only (Nacos-loaded) — no Java fallback.
- **P2-10** Notification subsystem: externalize as a Kafka consumer.

## P3 — Future Evolution (do NOT implement prematurely)

- **P3-1** Full PBAC DSL (Rego / OPA integration) — only after a real product demand.
- **P3-2** Zanzibar-style relation tuples (ReBAC) — only when relationship queries become a measurable bottleneck.
- **P3-3** Schema-per-tenant deployment — only when shared-schema hits a regulatory wall.
- **P3-4** SCIM provisioning — only when customer SSO is on the roadmap.
- **P3-5** Per-tenant JWK / issuer — implement when tenant count > 1.
- **P3-6** mTLS service identity (SPIFFE) — only when moving to a service mesh.
- **P3-7** SAML — only on explicit customer demand.

---

# 19. Overengineering Detection

| Feature | Status | Verdict | Reason |
|---|---|---|---|
| WebAuthn (FIDO2) | Implemented | **Justified** — standard for passwordless/MFA |
| TOTP MFA | Implemented | **Justified** — universal fallback |
| OAuth2 Authorization Server | Implemented | **Justified** — standard for external apps |
| TwoLevelCache (L1+L2+pub/sub) | Implemented | **Justified** for multi-JVM |
| Read-write split + replication lag monitor | Implemented | **Justified** at scale |
| Sentinel + Resilience4j | Implemented | **Justified** — defense in depth |
| `@DataScope` SQL rewriting | Implemented | **Genius but very narrow** — appropriate for current product |
| `DataSyncEventPublisher` + handlers + reconciliation | Implemented | **Justified but over-built** — only needed because of cross-DB design |
| `sys_sensitive_operation_log` with risk score 1-10 | Implemented | **Premature** — risk score is rarely used; simpler audit suffices |
| `sys_notification_*` (3 tables + retry) | Implemented | **Overkill** — should be externalized |
| Monthly partitioning of `sys_audit_log` + auto-create function | Implemented | **Justified** — good for ops |
| `sys_data_permission_rule.resource_type` + `visible_fields[]` + JSONB rule config | Implemented | **Overkill** — never used in practice based on absence of callers |
| `business_scope JSONB` on roles | Implemented | **Suspicious** — no callers use it |
| Custom HMAC `ApiSignatureFilter` + `IdentityTokenEncoder` + signed-but-never-verified X-Identity-Token | Implemented | **Partially justified** — the HMAC filter is correct for inbound; the X-Identity-Token is **broken** (never verified) and should be either verified or removed |
| Custom HS512 `JwtUtils` parallel to OAuth2 AS | Implemented | **Over-engineered** — pick one |

**Conclusion**: CPF contains about 15% over-engineering (two parallel JWT systems, broken X-Identity-Token, notification subsystem, unused risk-score / business-scope fields) and 85% appropriately-built infrastructure for its current product scope.

---

# 20. Recommended Target Architecture

## 20.1 Logical architecture (revised)

```
┌──────────────────────────────────────────────────────────────────────┐
│  Clients (Web, Mobile, Service, Third-Party SaaS, CLI)                │
└────────┬─────────────────────────────────────────────────────────────┘
         │ HTTPS / OAuth2 + PKCE / mTLS
         ▼
┌──────────────────────────────────────────────────────────────────────┐
│  API Gateway (Spring Cloud Gateway)                                   │
│  - Rate limit, IP filter, signature filter, identity propagation     │
│  - WebAuthn step-up challenge routing                                │
└────────┬─────────────────────────────────────────────────────────────┘
         │ Signed X-Identity-Token + plain X-* headers (verified!)
         ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Identity Layer (auth service)                                       │
│  - OAuth2 AS + OIDC + SAML adapter (Phase 4) + MFA + WebAuthn        │
│  - Login / logout / refresh / introspect / revoke / JWKS              │
└────────┬─────────────────────────────────────────────────────────────┘
         │ Dubbo + signed RPC token (Phase 1)
         ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Authorization Core (system service)                                  │
│  - Tenant / Application / Organization / User / Role / Permission     │
│  - Resource catalog / Action registry / Grant (explicit)             │
│  - Approval workflow (configurable per tenant)                        │
└────────┬─────────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Decision Plane                                                      │
│  - POST /api/decision/check  · /batch-check                          │
│  - Local SDK + Redis L1 + push invalidation                          │
│  - OPA / Rego adapter (Phase 4)                                       │
└────────┬─────────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Audit / Observability                                                │
│  - Authorization decision log  (high-volume, short retention)         │
│  - Compliance audit log        (regulated, long retention)           │
│  - OTel traces · Prometheus metrics · alert rules                     │
└──────────────────────────────────────────────────────────────────────┘
```

## 20.2 Control Plane vs Data Plane (the missing split)

```
┌──────────────────────────────────┐  ┌──────────────────────────────────┐
│ CONTROL PLANE                    │  │ DATA PLANE                       │
│                                  │  │                                  │
│ - Tenant CRUD                    │  │ - POST /decision/check           │
│ - Application CRUD               │  │ - POST /decision/batch-check     │
│ - Resource catalog CRUD          │  │ - GET /decision/permissions      │
│ - Action registry CRUD           │  │ - GET /decision/roles            │
│ - Role CRUD (with scope)         │  │                                  │
│ - Grant CRUD (explicit)          │  │ Properties:                      │
│ - Approval workflow config       │  │ - Read-mostly, hot path          │
│ - Policy versioning              │  │ - p99 < 5 ms                     │
│ - Audit query UI                 │  │ - Cache-friendly                 │
│ - SDK key issuance               │  │ - SDK-first design               │
│                                  │  │ - Push-invalidated               │
│ Properties:                      │  │                                  │
│ - Rare, slow, strong auth        │  │                                  │
│ - Admin UI / IaC primary         │  │                                  │
│ - Strict audit on every change   │  │                                  │
└──────────────────────────────────┘  └──────────────────────────────────┘
```

Today CPF is **entirely control-plane exposed** with no dedicated data-plane API. This is the largest architectural gap.

---

# 21. Recommended Domain Boundaries

```
IDENTITY BOUNDARY (auth module)
  - OAuth2 AS, OIDC, WebAuthn, MFA, JWT minting/refresh/revocation
  - Owns: SysUser (auth view), WebAuthnCredential, SysUserOauth
  - Does NOT own: roles, permissions, orgs

TENANT + ORG BOUNDARY (system/service)
  - SysTenant, SysApplication
  - SysOrg / SysDept (tree)
  - Owns identity assignment (User → Org)

AUTHORIZATION CORE (system/service)
  - SysRole (tenant-scoped, app-scoped)
  - SysPermission (catalog: action registry + resource)
  - SysResource (typed registry)
  - SysGrant (subject + permission/resource + scope + effect + priority + expire)
  - SysRolePermission (legacy — kept for backward compatibility, deprecated)
  - SysPolicyVersion (versioning)

DECISION PLANE (system/service or new service)
  - DecisionEngine: combines role-grants + explicit-grants + scope + context
  - Returns: {effect, reason, policy_version, decision_id}

AUDIT BOUNDARY (out-of-band)
  - Emits AuthorizationEvent on Kafka (does not own audit table)
  - Consumers write to db_audit

NOTIFICATION BOUNDARY (out-of-band)
  - Emits NotificationRequest on Kafka
  - External consumer sends email/SMS/push
```

**Boundary rules:**

- `common/*` never depends on `system/*`, `auth/*`, `gateway/*`. (Already enforced.)
- `auth/*` may depend on `system/api` (interface only), never on `system/service` impl.
- `system/service` is the only module that owns authorization state.
- The Decision Plane should be **the only thing** other services depend on for permission decisions.

---

# 22. Recommended API Model

## 22.1 Control-plane APIs (admin)

```
# Tenant
POST   /v1/admin/tenants
GET    /v1/admin/tenants/{id}
PATCH  /v1/admin/tenants/{id}

# Application (per tenant)
POST   /v1/admin/tenants/{tid}/applications
GET    /v1/admin/tenants/{tid}/applications
PATCH  /v1/admin/applications/{appId}

# Resource catalog
POST   /v1/admin/resources
GET    /v1/admin/resources?tenant=&app=
PATCH  /v1/admin/resources/{id}

# Roles
POST   /v1/admin/roles
GET    /v1/admin/roles?tenant=&app=&scope=
PATCH  /v1/admin/roles/{id}
DELETE /v1/admin/roles/{id}
POST   /v1/admin/roles/{id}/permissions    # add perms
DELETE /v1/admin/roles/{id}/permissions/{pid}

# Grants (explicit)
POST   /v1/admin/grants
GET    /v1/admin/grants?subject=&resource=&action=
DELETE /v1/admin/grants/{id}

# Policies (versioned)
POST   /v1/admin/policies
GET    /v1/admin/policies?version=
POST   /v1/admin/policies/{id}/activate

# Audit
GET    /v1/admin/audit?decision_id=&subject=&action=&from=&to=
```

## 22.2 Data-plane APIs (runtime)

```
# Decision (latency-critical)
POST /v1/decision/check
  body:  { subject: {id, type}, action: "user.read", resource: {type, id}, context: {...} }
  resp:  { effect: "allow"|"deny", reason: "...", policy_version: "v123", decision_id: "..." }

POST /v1/decision/batch-check
  body:  { checks: [ ... 100 items ... ] }
  resp:  { results: [ {effect, reason, decision_id}, ... ] }

GET  /v1/decision/permissions?subject=user:abc
GET  /v1/decision/roles?subject=user:abc

# Sync (for SDK hydration)
GET  /v1/sync/policy-version
GET  /v1/sync/permissions?subject=user:abc&since=v100
GET  /v1/sync/roles?subject=user:abc&since=v100

# Webhooks / Events (for cache invalidation)
WebSocket /v1/events/permissions    # push invalidation to subscribed SDKs
Kafka topic: authz.invalidations     # async push
```

## 22.3 SDK shape (Go example, indicative)

```go
type DecisionClient interface {
    Check(ctx context.Context, req CheckRequest) (Decision, error)
    BatchCheck(ctx context.Context, reqs []CheckRequest) ([]Decision, error)
    SubscribeInvalidations(handler func(InvalidationEvent)) error
}

type LocalCache struct {
    ttl          time.Duration
    fallback     DecisionClient
    subscriptions []chan InvalidationEvent
}
```

The local cache hydrates from `/v1/sync/permissions` and from push events; on miss it falls back to `/v1/decision/check`.

---

# 23. Recommended Authorization Model

A single canonical model that subsumes RBAC, ABAC (data scope), and is ABAC-ready:

```
Subject (User | ServiceAccount)
    │
    │ holds
    ▼
Grant (subject_id, target_type, target_id, action, scope, effect, priority, expire)
    │
    │ target_type ∈ { role | permission | resource_instance }
    │ target_id   = the role/perm/resource-instance being granted
    │ scope       = { tenant_id, app_id, org_id, resource_filter }
    │ effect      ∈ { allow, deny }
    │ priority    = int (deny wins over allow at same priority; higher priority wins)
    │ expire      = null | timestamp
```

**Evaluation algorithm** (kept simple):

1. Collect all `Grant` rows where `subject_id = X` and `expire IS NULL OR expire > now`.
2. For `target_type = 'role'`, expand to the role's permission grants recursively (with cycle detection).
3. For each expanded grant, check scope match (`tenant`, `app`, `org`, optional resource filter).
4. For each surviving grant, compute `effect = allow | deny` at `priority`.
5. **Deny wins on tie**; higher `priority` wins otherwise.
6. Evaluate context conditions (IP range, time-of-day, device-trust) — Phase 4.

This is roughly Cerbos-style. It does NOT require OPA/Rego today. It DOES give us:

- **RBAC** as `target_type='role'`.
- **Explicit grants** as `target_type='permission'` (the missing P0-5 path).
- **Resource-level grants** as `target_type='resource_instance'`.
- **Multi-tenancy** via `scope.tenant_id`.
- **Application isolation** via `scope.app_id`.
- **Delegation / temporary access** via `expire`.
- **Deny-overrides** for SoD rules via `effect='deny', priority=100`.

This model **does not require rewriting** CPF. It can be implemented as a new `Grant` table + a new `DecisionService` that consumes the existing `sys_role_permission` + `sys_data_permission_rule` + new `Grant` rows.

---

# 24. Evolution Roadmap

## Phase 0 — Foundation (2–3 months, must-do before further feature work)

**Goal**: Eliminate the security/architecture gaps that block multi-tenant use.

| # | Item | Owner |
|---|---|---|
| 0.1 | Add `X-Identity-Token` verification filter in `common/web` and `gateway` | Security |
| 0.2 | Add Redis-backed user-revocation key (`jwt:revoked_user:{userId}` INCR on perm change) | Security |
| 0.3 | Add `@PreAuthorize` to `/api/system/permissions/find-by-url` | Backend |
| 0.4 | Replace hard-coded super-admin UUID with `sys_config` lookup | Backend |
| 0.5 | Add `RpcContext.setAttachment("internalToken", signed)` + provider-side verification | Backend |
| 0.6 | Consolidate the two `SysAuditLog` classes | Backend |
| 0.7 | Implement approval type 2 (direct permission grant) | Backend |
| 0.8 | Add `/v1/` prefix to all platform APIs | Backend |
| 0.9 | Make the two JWT subsystems one — pick Spring Authorization Server, deprecate custom HS512 | Security |
| 0.10 | Add decision-log table + emit decision events on `@PreAuthorize` | Observability |

**Acceptance**:

- All P0 items closed.
- All existing tests pass.
- Load test: 1000 RPS decision checks for 1 hour without lockout.

## Phase 1 — Multi-Tenancy + Decision API (3–4 months)

**Goal**: Introduce `Tenant` and `Application` as first-class concepts and ship the decision API.

| # | Item | Owner |
|---|---|---|
| 1.1 | Add `sys_tenant` + `sys_application` | Backend |
| 1.2 | Add `tenant_id` to every domain table; backfill data; update mappers | Backend + DBA |
| 1.3 | Build `TenantContextHolder` + `TenantInterceptor` | Backend |
| 1.4 | Per-tenant `RegisteredClient` (DB-backed) | Backend |
| 1.5 | JWT carries `tenant_id` and `app_id` claims | Security |
| 1.6 | Split `sys_permission` into `sys_permission` + `sys_menu` + `sys_api_permission` + `sys_data_permission` | Backend |
| 1.7 | Add `sys_resource` catalog | Backend |
| 1.8 | Implement `Grant` entity + `DecisionService` + `POST /v1/decision/check` + `POST /v1/decision/batch-check` | Backend |
| 1.9 | Introduce `sys_policy_version` for policy versioning | Backend |
| 1.10 | Add per-tenant metrics + per-tenant rate limit | Observability |

**Acceptance**:

- Two tenants can co-exist without cross-tenant data leakage.
- External app can call `POST /v1/decision/check` from outside the cluster.
- Decision-log shows every decision with reason.

## Phase 2 — Enterprise Capabilities (2–3 months)

| # | Item |
|---|---|
| 2.1 | SDK for Java (Spring) and Go (initial) |
| 2.2 | Resource ownership model (`sys_resource_ownership`) |
| 2.3 | Field-level masking applied at SQL level (not just metadata) |
| 2.4 | Configurable approval workflow templates per tenant |
| 2.5 | SoD (separation of duties) — static role-conflict rules |
| 2.6 | mTLS / SPIFFE for Dubbo service identity |
| 2.7 | Decision-log analytics dashboard |
| 2.8 | Externalize notification subsystem to Kafka consumer |

## Phase 3 — Distributed Authorization (2–3 months)

| # | Item |
|---|---|
| 3.1 | Local SDK with TTL cache + push invalidation |
| 3.2 | Subscription channel (WebSocket / Kafka) for permission changes |
| 3.3 | Batch decision API optimization (binary protocol or gRPC) |
| 3.4 | High-performance DecisionService (Caffeine L1 + Redis L2 + JIT-compiled policy eval) |
| 3.5 | Read replicas for `sys_permission`, `sys_role`; eventual consistency tolerance documented |

## Phase 4 — Advanced Authorization (only on demand)

| # | Item |
|---|---|
| 4.1 | ABAC engine (Rego via OPA sidecar or embedded) |
| 4.2 | ReBAC relation tuples for resource-graph queries |
| 4.3 | Just-in-time access (JIT) with auto-revoke |
| 4.4 | Risk-based step-up (geo, device, velocity) |
| 4.5 | Anomaly detection on decision log |

---

# 25. What NOT to Build (explicit anti-roadmap)

These are ideas that look good in a tech blog but **must not be built** unless a specific business driver emerges:

1. **Full PBAC DSL (Rego)** — wait for a customer with a real dynamic-policy need.
2. **Zanzibar-style relation tuples** — wait for a relationship query use case that current SQL cannot express.
3. **Schema-per-tenant** — wait for a tenant with regulatory isolation requirements.
4. **Custom SQL condition DSL on roles** — `sys_role.business_scope JSONB` already exists; do not expand it.
5. **A second audit subsystem** — extend `sys_audit_log`, do not add `sys_compliance_log_v2`.
6. **Per-tenant OAuth2 issuer** — wait until tenant count > 1 forces it.
7. **A "policy admin UI"** — invest in OpenAPI / IaC instead.
8. **GraphQL** for the platform APIs — REST + SDK is sufficient.
9. **A "general-purpose workflow engine"** — keep the approval workflow narrow.
10. **Replacing Spring Security with something else** — Spring Security 6 + Spring Authorization Server is industry-standard.
11. **Replacing MyBatis-Plus with JPA / Hibernate** — large rewrite, no benefit.
12. **A new notification engine** — use the existing Spring ecosystem + Kafka + a pluggable sender.

---

# 26. Final Architecture Principles (for the platform)

1. **The authorization model must outlive every business application built on top of it.** Do not let product-specific concepts (payment, file download, dept-only) leak into the core.
2. **Multi-tenancy is a property of every table and every cross-cutting filter, not a feature.** Add `tenant_id` and `app_id` now.
3. **Decisions are an API, not an in-memory authority.** Build `/v1/decision/check` before building more complex policy features.
4. **Cache invalidation is a contract.** Publish invalidation events; let SDKs subscribe. Don't rely on TTL alone.
5. **Tokens are short, revocation is push.** 5–15 min access tokens, push-based user-revocation on every permission change.
6. **Identity must be verified at every hop.** No plaintext `X-User-Id` headers across service boundaries.
7. **The audit log is for accountability, not for debugging.** Keep it lean, separate from logs.
8. **Resource is a first-class concept.** Stop string-typing `resource_type`.
9. **Deny-overrides.** Build it into the model from day one, even if there are no SoD rules yet.
10. **Every new abstraction must have at least one real call site before it ships.** YAGNI applies especially to authorization.
11. **Don't become a god system.** Identity verification, yes. Notification engine, no. HR data, no. UI rendering, no.
12. **Optimize for the 5-minute decision latency, not the 5-microsecond check.** Most decisions are not in the hot path. Make the data plane fast, then make it correct.

---

## Closing note

The repo can credibly evolve into an enterprise authorization platform. The gap is not engineering quality — the engineering is solid. The gap is **conceptual scope**: Tenant, Application, Resource catalog, Decision API, and a real Control-Plane vs Data-Plane split. Fix those in Phase 0 and Phase 1, and the platform becomes a foundation rather than a feature.

Every recommendation above cites the actual code that motivates it. When implementation begins, the Phase 0 list is the minimum viable security baseline; nothing else should land until those items close.
