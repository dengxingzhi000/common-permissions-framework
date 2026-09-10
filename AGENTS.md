# Repository Guidelines

## What this is
Spring Boot 4 / Spring Cloud 2025 multi-module microservices permission framework. Java 21, Lombok, MyBatis-Plus, Nacos, Redis, PostgreSQL, Kafka/RabbitMQ. Repo artifact is `common-permissions-framework`; IntelliJ module file may show `NewNearSync` — same project.

## Module layout (from `pom.xml`)
```
common/                      # Parent aggregator — empty, just groups
├── core                     # Plain-Java utils (UUIDv7, exceptions, PageResult). No Spring.
├── security-api             # Security DTOs/interfaces shared across services
├── monitoring               # Sentinel circuit breaker
├── integration              # Kafka/RabbitMQ messaging (MessageEnvelope, reconciliation)
├── data                     # MyBatis-Plus, caching, DataScope, read-write split (@Master/@Slave)
├── web                      # Security filters, JWT, Feign clients, UAA server config
│   └── securityCore         # SecurityUser domain objects
├── system/api               # Dubbo service interfaces (NO impl)
├── system/service           # Domain services + Dubbo providers
├── auth                     # OAuth2/WebAuthn/JWT auth service (HTTPS only)
└── gateway                  # Spring Cloud Gateway (entry point)
```
Rule: services may depend on `common/*`; `common/*` MUST NOT depend on services or `system/*`.

## Build & run

```bash
mvn clean install                # everything, runs tests
mvn clean install -DskipTests    # skip tests when local suite is known green
mvn test -pl common/data -am     # one module + its deps; far faster than root
mvn package -DskipTests -pl auth,gateway,system/service -am   # build runnable jars
```

**Service startup order is mandatory** (depends on Dubbo):
```bash
# 1. system/service — exposes Dubbo providers
cd system/service && mvn spring-boot:run
# 2. auth — consumes system Dubbo services
cd ../../auth && mvn spring-boot:run
# 3. gateway — consumes everything; entry point on :8761 (override via SERVER_PORT)
cd ../gateway && mvn spring-boot:run
```
CLI default ports: `gateway 8761`, `auth 8106 (HTTPS)`, `system/service 8081`. Docker compose overrides these via `SERVER_PORT` env (gateway → 9095, auth → 8082).

Dependencies (Nacos + Redis + Postgres) via `docker-compose.yaml` at the **repo root** (not under `auth/src/main/resources/` — that older copy still exists).

## Tests

CI (`/.github/workflows/ci.yaml`) runs `mvn test -pl common/core,common/data,common/monitoring,common/integration,system/service -am` against Postgres+Redis services. `common/web`, `common/security-api`, `common/web/securityCore`, `auth`, `gateway`, `system/api` are only **compiled and packaged**, not unit-tested in CI.

Useful single-test invocations:
```bash
mvn test -pl common/web -Dtest=JwtUtilsTest
mvn test -pl common/web -Dtest=JwtUtilsTest#testGenerateToken
mvn test -pl common/data -Dtest=DataScopeInterceptorTest
./run-tests.sh --security        # JWT + permission + SQL-injection suite
./run-tests.sh --coverage        # adds JaCoCo report
```

**Test-dep gotcha:** any new module with tests must declare `spring-boot-starter-test` with `<scope>test</scope>`. The parent `pom.xml` provides the version in `dependencyManagement`. Missing this causes CI to fail at `testCompile` with `package org.junit.jupiter.api does not exist`. See `common/integration/pom.xml` for the canonical pattern.

## Required env / secrets

`auth` and `gateway` won't start without:
- `JWT_SECRET` — **must decode to ≥ 64 bytes** (`JwtUtils.java:48` throws `IllegalArgumentException` otherwise). HS512 signing. Don't reuse the CI test secret in prod.
- `API_SIGNING_SECRET`, `IDENTITY_TOKEN_SECRET` — HMAC keys, no enforced length.
- `DB_HOST/PORT/NAME/USERNAME/PASSWORD`, `REDIS_HOST/PORT`, `NACOS_SERVER/NAMESPACE/GROUP` — all required.

`docker-compose.yaml` ships with development-only secrets (`postgres/postgres`, base64 test JWT key). Override before any non-local use.

## Local-only files (must NOT be committed)
`.gitignore` covers `application-local.*`, `application-dev.*`, `application-test.*` plus `*.iml`, `.idea/*` (except `.idea/.gitignore`), and IDE/maven build output. The `skills/` and `.opencode/skills` symlink target were stray Anthropic skills — kept on disk, removed from git in `f9883c8`.

## Commit & PR
Conventional commits, bilingual summaries welcome (`fix(common.integration): 添加缺失的 spring-boot-starter-test 测试依赖`). Scope matches module: `common.integration`, `gateway`, `system.service`, etc. PRs need `mvn test` (or targeted module tests) green; describe risk; link issue IDs; flag any Nacos config or chart changes.

CI merges to `master` are gated by `/.github/workflows/ci.yaml`. `ci-cd.yaml` is a separate legacy full-stack pipeline (build+push+helm deploy) that requires registry secrets — ignore unless doing releases.

## Architecture deep-dive
`CLAUDE.md` covers security filter chains, DataScope, read-write split, TwoLevelCache, Kafka/RabbitMQ envelope conventions, Resilience4j tunings, and known caveats (~440 lines). Read it before touching security, data scope, or messaging code.

## Conventions worth knowing
- Package root: `com.frog.<module>.<layer>` — lowercase, dot-separated.
- All controllers return `ApiResponse<T>`. Use `@Valid` on DTOs.
- Lombok on (`@Data`, `@Builder`, `@Slf4j`); don't write getters/setters/loggers by hand.
- PKs are UUIDv7 (`UUIDv7Util.generate()`); soft-deletes via `deleted` column with `@TableLogic`.
- Hard-coded secrets in source will be rejected in code review — read from `JWT_SECRET` / Nacos / `@ConfigurationProperties`.

## OpenCode-specific
- `.opencode/skills` is a symlink to `../skills/` (still present locally for IDE integration).
- `opencode.jsonc` enables CodeGraph MCP — prefer `codegraph_explore` for "where is X / how does Y work" over grep+read.
- `.codegraph/` index may be present; rebuild via `codegraph init` if it goes stale.
