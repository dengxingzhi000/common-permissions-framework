# Phase 0 — Foundation 设计文档

> **For**: CommonPermissionsFramework (`common-permissions-framework`)
> **Status**: Draft v1 — awaiting user review
> **Parent review**: `docs/architecture-review.md`
> **Author**: Principal Architect + Enterprise Security Architect
> **Date**: 2026-09-19

---

## 1. 目标与范围

关闭架构评审中识别的 **P0 安全缺陷**,为 Phase 1 多租户 + 决策 API 奠定安全基线。

**In scope (Phase 0)**:

| # | 项目 | 类别 | 工作量估时 |
|---|---|---|---|
| 0.1 | `X-Identity-Token` 验证过滤器 | 安全 | 1 周 |
| 0.2 | 用户级 Token 撤销机制 | 安全 | 1 周 |
| 0.3 | `/api/system/permissions/find-by-url` 加 `@PreAuthorize` | 安全 | 半天 |
| 0.4 | 用 `sys_config` 替换硬编码超管 UUID | 清理 | 1 天 |
| 0.5 | Dubbo 调用身份验证 (RpcContext internalToken) | 安全 | 1 周 |
| 0.6 | 合并两套 `SysAuditLog` 类 | 清理 | 2 天 |
| 0.7 | 审批 type=2 直接权限授予 | 功能补完 | 3 天 |
| 0.8 | 全平台 API 加 `/v1/` 前缀 | 重构 | 3 天 |
| 0.9 | 合并两套 JWT (HS512 → 统一 OAuth2 AS) | 重构 | 2 周 |
| 0.10 | 决策日志表 + `@PreAuthorize` 评估事件 | 可观测性 | 1 周 |

**总估时**: ~ 7-8 周 (1-2 人)

**Out of scope**:
- 多租户表结构 (`sys_tenant`, `tenant_id` 列) — Phase 1.1 / 1.2
- 决策 API (`POST /v1/decision/check`) — Phase 1.8
- `Grant` 实体 — Phase 1.8
- `Application` 实体 — Phase 1.1

---

## 2. 执行顺序与依赖图

```
Wave 1 (基础清理,可并行)
   0.3 ──► (独立)
   0.4 ──► (独立)

Wave 2 (安全核心,可并行;依赖 Wave 1 已落地的代码风格)
   0.1 ──► 验证过滤器
   0.5 ──► Dubbo internalToken (顺手修复 @DubboReference 缺失)
   0.6 ──► SysAuditLog 合并
   0.7 ──► 审批 type=2
   0.10 ─► 决策日志 (需要 0.1 已经验证身份才能区分是谁的决策)

Wave 3 (集成层)
   0.2 ──► 用户级撤销 (依赖 0.1 / 0.5 已就绪)
   0.9 ──► JWT 合并 (依赖 0.1 / 0.5 / 0.6 已稳定)

Wave 4 (收尾)
   0.8 ──► /v1/ 前缀 (最后,所有接口在切换时已稳定)
```

**关键依赖**:
- 0.2 (撤销) 必须在 0.1 (身份验证) 之后——撤销是绑在用户身份上的
- 0.9 (JWT 合并) 必须在 0.6 (SysAuditLog 合并) 之后——审计日志会读 token claim
- 0.8 (版本化) 必须放最后——避免中途改动路径

---

## 3. 数据库迁移

所有 schema 变更走 **Flyway**,新文件命名 `V{next}__*.sql`。

| 项 | 新表 / 改动 | SQL 文件 |
|---|---|---|
| 0.2 | 无 (用 Redis Hash) | — |
| 0.4 | 新增 `sys_config(id, config_key UNIQUE, config_value, scope, tenant_id, status, audit)` | `V20260920_01__add_sys_config.sql` |
| 0.6 | 改 `sys_audit_log.status` 类型 (`SMALLINT` → 保持); 检查 PK `(id, create_time)` 与 AUTO 注解冲突 | 无新表 |
| 0.10 | 新增 `sys_decision_log(id, decision_id UNIQUE, ts, subject_type, subject_id, action, resource_type, resource_id, context_jsonb, effect, reason, policy_version, request_id, latency_ms, audit)` 按月分区 | `V20260920_02__add_sys_decision_log.sql` |

**数据回填**: 仅 0.4 需要——把硬编码 UUID `019a0aee-3b74-7bfc-b34f-48b5428d4875` 写入 `sys_config` 行 `super_admin_user_id`。

---

## 4. 新增 / 修改配置项

| 项 | Nacos 配置 | 默认值 | 说明 |
|---|---|---|---|
| 0.1 | `security.identity-propagation.enabled` | `true` | 总开关 (默认严格) |
| 0.1 | `security.identity-propagation.shared-secret` | (从 ENV `IDENTITY_SIGNING_SECRET` 取, ≥ 32 字节) | HMAC-SHA256 共享密钥 |
| 0.1 | `security.identity-propagation.max-skew-seconds` | `30` | issuedAt 容忍偏差 |
| 0.2 | `security.token-revocation.enabled` | `true` | 用户级撤销开关 |
| 0.5 | `dubbo.internal-token.shared-secret` | (从 ENV `DUBBO_INTERNAL_SECRET` 取, ≥ 32 字节) | Dubbo 调用签名密钥 |
| 0.5 | `dubbo.internal-token.ttl-seconds` | `60` | internalToken TTL |
| 0.8 | `server.servlet.context-path` | (空) | 不强制;用 route 重写实现 /v1 前缀 |
| 0.9 | `security.oauth2.authorizationserver.issuer` | (已有) | OAuth2 AS 颁发者 |
| 0.9 | `security.jwt.enabled` | `true` | 旧 HS512 路径开关,默认 false(关闭) |
| 0.10 | `observability.decision-log.enabled` | `true` | 决策日志总开关 |

---

## 5. 每项详细设计

### 0.1 — `X-Identity-Token` 验证过滤器

**问题**: gateway 生成的 HMAC 签名身份令牌从未被下游验证,任何能到达后端的请求都能伪造 `X-User-Id`。

**改动**:

1. **新增** `common/web/src/main/java/com/frog/common/security/identity/IdentityTokenVerifier.java`
   - `verify(String identityToken, String rawUserId, String rawRoles) → VerifyResult`
   - `VerifyResult { ok: boolean, payload: Map<String,Object>, reason: String }`
   - HMAC-SHA256 重算 + issuedAt 时戳校验 (≤ 30s)

2. **新增** `common/web/src/main/java/com/frog/common/security/filter/IdentityTokenVerificationFilter.java`
   - 跑在 `JwtAuthenticationFilter` **之前** (`SecurityConfig.java:142-144` 调整顺序)
   - 跳过白名单: `/api/auth/login`, `/api/auth/refresh`, `/actuator/health`, `/oauth2/**`, `/api/public/**`
   - 验证失败 → 401 + `IdentityErrorCode.IDENTITY_TOKEN_MISSING` 或 `IDENTITY_TOKEN_INVALID` 或 `IDENTITY_TOKEN_EXPIRED`

3. **新增** `gateway/src/main/java/com/frog/gateway/security/IdentityTokenVerificationWebFilter.java` (WebFlux 版本)
   - 等价于 servlet 版本,跑在 `SecurityWebFilterChain` 内,order = `SecurityWebFiltersOrder.AUTHENTICATION.getOrder() - 1`
   - 跳过 gateway 自身公开路径: `/api/auth/**`, `/actuator/health`, `/oauth2/**`

4. **修改** `IdentityPropagationWebFilter.java:80-98`
   - **`issuedAt` 改为请求时间戳**(已实现)
   - **加 jti** 防止重放 (UUIDv7)
   - payload 增加 `appId`(从 JWT claim 读)

5. **修改** `IdentityPropagationProperties.java`
   - 新增字段: `sharedSecret`(优先), `maxSkewSeconds`, `failureMode`(`strict` | `log-and-pass`,默认 `strict`)

**数据库 / 配置变更**:
- 无表变更
- 新增 Nacos 配置 (见 §4)

**测试矩阵**:
| 场景 | 期望 |
|---|---|
| 缺 `X-Identity-Token` | 401 IDENTITY_TOKEN_MISSING |
| 签名错误 (篡改 payload) | 401 IDENTITY_TOKEN_INVALID |
| issuedAt 超过 30s | 401 IDENTITY_TOKEN_EXPIRED |
| jti 重复 (重放) | 401 IDENTITY_TOKEN_REPLAY |
| payload userId ≠ X-User-Id | 401 IDENTITY_USERID_MISMATCH |
| 完整有效 token | 通过,后续过滤器正常处理 |
| 白名单路径 | 跳过验证 |

**回滚**:
- 配置 `security.identity-propagation.enabled=false` → 旧行为
- 移除 filter 注册即可

**验收**:
- [ ] 单元测试覆盖所有失败场景 + 通过场景
- [ ] 集成测试: gateway → 后端,篡改 userId 请求被拒
- [ ] 压测: 验证过滤器增加延迟 < 0.5ms p99

---

### 0.2 — 用户级 Token 撤销机制

**问题**: 现有撤销仅 per-jti 黑名单,用户改密/吊销/调岗后,**未过期的 access token 仍有效**,且 JWT 内嵌的权限码会迟到下一次刷新。

**改动**:

1. **新增** `common/web/src/main/java/com/frog/common/security/revocation/UserRevocationService.java`
   - `revokeUser(UUID userId, String reason) → long` 返回新版本号
   - `revokeUserDevice(UUID userId, String deviceId) → long`
   - `getCurrentVersion(UUID userId, String deviceId) → long`
   - Redis 结构: `Hash jwt:revoked_ver:{userId} → {deviceId → version}` (version 是单调递增 long)
   - 兜底: `jwt:revoked_ver:{userId}:all → version` (全设备撤销)

2. **修改** `JwtAuthenticationFilter.java:44-101`
   - 解析 token 后,在第 58 行 `validateToken` 通过后,新增:
     ```java
     long tokenIssuedAt = jwtUtils.getIssuedAtFromToken(token);
     long currentVersion = userRevocationService.getCurrentVersion(userId, deviceId);
     if (tokenIssuedAt < currentVersion) {
         // 该设备上此 token 颁发后用户被撤销过,拒绝
         SecurityErrorResponseWriter.write(...401...);
         return;
     }
     ```
   - **保持**现有 per-jti 黑名单,不删除

3. **新增** `common/web/src/main/java/com/frog/common/security/revocation/RevocationEventPublisher.java`
   - 监听 `DataSyncEvent` 中的 `UserUpdated`,如果 `status` 字段变为 0 (禁用) 或被踢出 → 触发撤销
   - 监听 `PermissionChangeEvent` (来自 0.10 决策日志的副作用) → 触发 user 级撤销

4. **修改** `SysAuthServiceImpl.java:171-185` (`logout` 方法)
   - 登出时调用 `userRevocationService.revokeUserDevice(userId, deviceId)`

5. **修改** `SysUserServiceImpl.java` (禁用/删除用户方法)
   - 调用 `userRevocationService.revokeUser(userId, "user_disabled")`

**数据库 / 配置变更**: 无表变更;新增 Nacos 配置。

**测试矩阵**:
| 场景 | 期望 |
|---|---|
| 用户登出后旧 token | 401 TOKEN_REVOKED |
| 管理员禁用用户,该用户所有设备上的 token | 401 TOKEN_REVOKED |
| 单设备登出 (踢出其他设备) | 仅该设备撤销 |
| 同一用户其他设备的 token | 仍可用 |
| Redis 不可达 (故障注入) | 拒绝通过 (fail-closed),日志告警 |

**回滚**: `security.token-revocation.enabled=false` → 旧 per-jti 路径。

**验收**:
- [ ] 集成测试: 用户禁用后,持有 1h 前签发 token 的请求被拒
- [ ] 集成测试: 同一用户 device A 登出,device B 的 token 仍可用
- [ ] Redis 故障 → 100% 拒绝(避免绕过)

---

### 0.3 — `/api/system/permissions/find-by-url` 加权限校验

**问题**: 任何已认证用户可枚举"哪个 URL 由哪个权限码保护",信息泄露。

**改动**:

1. **修改** `system/service/src/main/java/com/frog/system/controller/SysPermissionController.java:163-172`
   - 现有方法签名加 `@PreAuthorize("hasAuthority('system:permission:query') or hasAuthority('system:admin')")`

2. **修改** `scripts/db/microservices/003_db_permission.sql` (后续 Flyway 迁移文件 `V20260920_03__seed_system_permission_query.sql`)
   - seed 一行 `permission_code='system:permission:query'`, `permission_type=3`(按钮),`need_approval=false`
   - 把该权限授予 super admin 角色 (`sys_role_permission`)

3. **修改** 现有 super admin role 权限 (在初始化数据里)

**数据库变更**: 仅 seed 数据,无结构改动。

**测试**:
- [ ] 无 `system:permission:query` 权限的普通用户 → 403
- [ ] super admin → 200 + 数据
- [ ] 匿名 → 401

**回滚**: 移除注解,无需其他动作。

---

### 0.4 — `sys_config` 替换硬编码超管 UUID

**问题**: `SysUserServiceImpl.java:295`, `SysRoleServiceImpl.java:157,195` 三个地方硬编码 `019a0aee-3b74-7bfc-b34f-48b5428d4875`,无法支持多租户。

**改动**:

1. **新增 Flyway** `common/data/src/main/resources/db/migration/V20260920_01__add_sys_config.sql`
   ```sql
   CREATE TABLE sys_config (
       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
       config_key VARCHAR(128) NOT NULL,
       config_value TEXT NOT NULL,
       scope VARCHAR(32) NOT NULL DEFAULT 'GLOBAL',  -- GLOBAL | TENANT
       tenant_id UUID,
       description TEXT,
       status SMALLINT NOT NULL DEFAULT 1,
       create_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
       update_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
       UNIQUE (config_key, tenant_id),
       CHECK (scope IN ('GLOBAL', 'TENANT'))
   );
   -- 初始数据:迁移 3 处硬编码 UUID
   -- 注:role 与 user 在 legacy 代码里使用了同一个 UUID (019a0aee-...),
   --     这是已存在的数据缺陷;真实角色 ID 需在迁移前从 db_permission.sys_role
   --     查询得出后回填,此处仅占位。PR 实施时务必 SELECT 出真实 role_id 再写死。
   INSERT INTO sys_config (config_key, config_value, description) VALUES
       ('super_admin_user_id', '<FILL_FROM_DB_AT_MIGRATION_TIME>', 'Built-in super admin user UUID (legacy)'),
       ('super_admin_role_id', '<FILL_FROM_DB_AT_MIGRATION_TIME>', 'Built-in super admin role UUID (legacy)');
   ```

2. **新增** `common/data/src/main/java/com/frog/common/config/SysConfigService.java`
   - `getString(String key)`, `getString(String key, String tenantId)` (租户覆盖优先)
   - 5 分钟 Caffeine cache (`@Cacheable("sysConfig", key="#key + ':' + #tenantId")`)

3. **修改** `SysUserServiceImpl.java:295` 与 `SysRoleServiceImpl.java:157,195`
   - 替换 `UUID.fromString("019a0aee-...")` 为 `sysConfigService.getString("super_admin_user_id")` 后 parse

**数据库**: 新表 `sys_config`。

**测试**:
- [ ] 单元: `SysConfigService` cache 命中/失效
- [ ] 集成: 删除/修改超管 → 业务行为正确(超管仍不可删,普通用户不受影响)

**回滚**: SQL DROP TABLE;代码 revert。

---

### 0.5 — Dubbo 调用身份验证

**问题**: 任何内部服务都能调用 `UserDubboService.findAllPermissionsByUserId(anyUserId)`,无身份。

**改动**:

1. **新增** `common/integration/src/main/java/com/frog/common/integration/dubbo/InternalTokenSigner.java`
   - `sign(String callerService, String callerUser, long ttlSeconds) → String` (HMAC-SHA256)
   - `verify(String token, String callerService) → VerifyResult`

2. **新增 Dubbo Filter** `common/integration/src/main/java/com/frog/common/integration/dubbo/InternalTokenFilter.java`
   - 实现 `org.apache.dubbo.rpc.Filter`
   - **服务端** (`provider`): 从 `RpcContext.getServerAttachment().getAttachment("internal-token")` 取出,verify,失败抛 `RpcException`
   - **客户端** (`consumer`): 从 `CallerContext` (Spring `RequestAttributes`) 取出 caller,sign 后 `RpcContext.getClientAttachment().setAttachment("internal-token", signed)`
   - **匿名调用**(系统内部,如定时任务): 用 `service-account:{appName}` 作为 caller

3. **新增** `common/integration/src/main/java/com/frog/common/integration/dubbo/CallerContext.java`
   - 封装 ThreadLocal: `currentUserId`, `currentTenantId`(Phase 1 时填充),`sourceService`
   - 与 `DataScopeContextHolder` 同模式

4. **修改** `auth/src/main/java/com/frog/auth/AuthApplication.java:31`
   - `@EnableDubbo(scanBasePackages = "com.frog")` 保留
   - **同时**修复 `SysAuthServiceImpl.java:54` `UserDubboService userDubboService` 字段加 `@DubboReference(version="1.0.0", check=true, timeout=3000)`

5. **修改** `system/service/src/main/java/com/frog/system/rpc/UserDubboServiceImpl.java` 与 `PermissionDubboServiceImpl.java`
   - 服务端日志加上 caller 信息(便于审计)

6. **修改** Dubbo 配置文件 (Nacos `common.yaml`)
   - 加 `dubbo.provider.filter=internalToken` 与 `dubbo.consumer.filter=internalToken`
   - 新增 `dubbo.internal-token.shared-secret` (从 ENV)

**数据库 / 配置**: 新增 Nacos 配置。

**测试**:
- [ ] 单元: `InternalTokenSigner.sign/verify` round-trip
- [ ] 单元: token 篡改 / 过期 / caller 不匹配 → 拒绝
- [ ] 集成: gateway → auth → system/service 全链路通过
- [ ] 集成: 外部伪 caller 调用 → 失败

**回滚**: 关闭 `dubbo.internal-token.enabled=false` 跳过 filter。

**验收**:
- [ ] 所有现有 Dubbo 调用方接入 (auth, gateway)
- [ ] 失败调用方有监控告警 (Micrometer `dubbo.internal_token.failures`)

---

### 0.6 — 合并两套 `SysAuditLog`

**问题**:
- `system/service/.../domain/entity/SysAuditLog.java` **不存在** (只有 `common/web` 的)
- `common/web/.../entity/SysAuditLog.java` 用 `@TableId(type=AUTO)` 但表用 UUID PK + 复合主键 `(id, create_time)`,写入必失败

**改动**:

1. **核实** 现有两类的实际使用情况
   - 全文 grep `SysAuditLog`(类名)+ `sys_audit_log`(表名) 找出所有写入点

2. **统一实体位置**:`common/security-api/src/main/java/com/frog/common/security/audit/SysAuditLog.java`
   - **纯 POJO**,无 MyBatis-Plus 注解(`common/security-api` 必须保持无 Spring 依赖)
   - `@TableId` 注解迁移到 `common/data/src/main/java/com/frog/common/data/audit/SysAuditLogPO.java`
   - 删除 `common/web/.../entity/SysAuditLog.java`(它带 MyBatis-Plus 注解且 ID 类型错误)

3. **统一 Mapper**:`common/data/src/main/java/com/frog/common/data/audit/SysAuditLogMapper.java`
   - 所有写入路径(原 `SysAuditLogAspect`、业务 service)改用此 mapper

4. **修改** `common/web/src/main/java/com/frog/common/log/aspect/SysAuditLogAspect.java`
   - 注入新 mapper,移除对 `SysAuditLog` 错误类的引用

5. **检查并修复** `sys_audit_log` 表 PK 定义
   - 当前 `005_db_audit.sql:45-46` 用 `PRIMARY KEY (id, create_time)`,与 entity 的 `IdType.AUTO` 不一致
   - 实体 `@TableId` 改为 `IdType.ASSIGN_UUID`;`create_time` 用 `@TableField(exist=false)` 标识为分区键

6. **新增 Flyway**(如必要) `V20260920_04__fix_audit_log_pk.sql` — 仅当现有 PK 定义需要修正时(需执行前手动核对 `db_audit.sys_audit_log` 实际约束)

**数据库**: 可能 PK 调整;**写入路径统一**。

**回滚**: revert 类文件迁移。

---

### 0.7 — 审批 type=2 直接权限授予

**问题**: `SysPermissionApprovalServiceImpl.java:209-211` 是 TODO,`approval_type=2` (permission request) 申请通过后什么都不做。

**改动**:

1. **修改** `system/service/.../service/Impl/SysPermissionApprovalServiceImpl.java:200-230` (`grantPermissions` switch)
   - 新增 case `2`(direct permission grant):
     - 调用新增的 `CrossDatabaseQueryService.batchInsertUserPermissions(targetUserId, permissionIds, currentUserId)`
   - 写入 `sys_temp_permission`(或新表 `sys_user_permission`, 见设计抉择)

2. **新增** `system/service/.../service/CrossDatabaseQueryService.java:batchInsertUserPermissions(...)`
   - 跨库写 `db_permission.sys_user_permission` (新建)
   - 或直接写 `sys_temp_permission`(若选 reuse)

3. **新增 Flyway** `V20260920_05__add_sys_user_permission.sql`
   ```sql
   CREATE TABLE sys_user_permission (
       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
       user_id UUID NOT NULL,
       permission_id UUID NOT NULL REFERENCES sys_permission(id) ON DELETE CASCADE,
       effective_time TIMESTAMPTZ,
       expire_time TIMESTAMPTZ,
       granted_by UUID,
       grant_reason TEXT,
       create_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
       UNIQUE (user_id, permission_id)
   );
   ```
   (决策: 用新表而不是 sys_temp_permission,因为后者语义是临时)

4. **修改** `CustomPermissionEvaluator.hasPermission()` 实现
   - `findAllPermissionsByUserId` 改为联合 `sys_user_role → sys_role_permission` ∪ `sys_user_permission`
   - 配合 `@CacheEvict`

5. **修改** `SysPermissionController.java` 加 API `POST /api/system/users/{userId}/grant-permissions`(同样需要 `@PreAuthorize('system:permission:grant')`)

**测试**:
- [ ] type=2 申请审批通过 → 用户实际获得权限
- [ ] 撤销: 删 `sys_user_permission` → `@CacheEvict` 后权限消失
- [ ] type=2 + expireTime → 到期自动清理 (`PermissionExpiryTask`)

---

### 0.8 — 全平台 API 加 `/v1/` 前缀

**问题**: API 无版本化,任何字段/路径变更都是 breaking。

**改动**:

1. **修改** 所有 controller `@RequestMapping` 前缀
   - `auth` 模块: `/api/auth/*` → `/v1/api/auth/*`(`SysAuthController`, `WebAuthnCredentialController`, `OAuth2LogoutController`)
   - `system/service` 模块: `/api/system/*` → `/v1/api/system/*`
   - OAuth2 AS 端点保持默认路径(Spring Authorization Server 标准化,前缀无法直接加 v1,而是 `oauth2/` 已稳定)
   - **例外**: actuator, swagger 不加前缀

2. **新增** route alias 配置 (Nacos `gateway.yaml`)
   ```yaml
   spring.cloud.gateway.routes:
     - id: auth-v1
       uri: lb://auth-service
       predicates:
         - Path=/v1/api/auth/**,/oauth2/**,/api/auth/webauthn/**
       filters:
         - StripPrefix=2  # 去掉 /v1/api 前缀,后端收到 /auth/**
   ```
   - 老路径 `/api/auth/**` 保留 6 个月,响应头加 `Deprecation: true` + `Sunset: Mon, 01 Mar 2027 00:00:00 GMT`

3. **修改** SecurityConfig 放行路径白名单
   - `/v1/api/auth/login` 等加入白名单

**数据库**: 无。

**测试**:
- [ ] 集成测试: 所有原路径走 gateway 仍工作(Deprecation 头存在)
- [ ] 新路径 `/v1/api/auth/login` 直接走后端也工作

**回滚**: route 配置关闭 `/v1/` 路由,回到旧路径。

---

### 0.9 — 合并两套 JWT (HS512 → 统一 OAuth2 AS)

**问题**: 同时存在 `JwtUtils` (HS512) 和 `AuthorizationServerConfig` (RSA),两套签发/验证/撤销/claim 命名,维护负担翻倍。

**改动**:

1. **Authentication Server 重构**
   - 保留 `AuthorizationServerConfig` (Spring Authorization Server)
   - 增加 `JwtMigrationService.java`,把 `JwtUtils` 的所有 claim 字段 (`userId`, `deptId`, `roles`, `permissions`, `deviceId`, `ipAddress`, `amr`, `jti`) 全部加到 OAuth2 AS 自定义 token enhancer
   - 删除 `JwtUtils.generateAccessToken` 路径,标记 `@Deprecated`

2. **两阶段发布**
   - **Phase 0.9a**: OAuth2 AS 同时签发新格式;`JwtUtils` 同时能验证新格式
   - **Phase 0.9b**: 客户端全部迁移到新格式;`JwtUtils` 删除验证逻辑,只留空壳
   - **Phase 0.10a**: `JwtUtils` 整体删除

3. **OAuth2 AS JWK 配置强化**
   - 强制从 keystore 读,启动失败若 keystore 缺失 (CLAUDE.md 提到 ephemeral fallback,生产禁用)
   - 加 `kid` 支持多 key 共存(为后续 rotation 做准备)

4. **修改** 所有 controller 的 token 解析
   - 从 `JwtUtils.getUserIdFromToken(token)` 改到 `OAuth2TokenDecoder.decode(token).getClaim("userId")`
   - 提供统一抽象 `TokenIntrospector` 接口

5. **修改** `JwtAuthenticationFilter`
   - 不再依赖 `JwtUtils`,依赖 `TokenIntrospector`
   - 验证逻辑委托 OAuth2 RS + 自定义 claim 校验

6. **删除** `common/web/.../security/util/JwtUtils.java`(最终阶段)

**测试**:
- [ ] 老 HS512 token 在过渡期仍可用(向后兼容读)
- [ ] 新 OAuth2 token 包含原所有 claim
- [ ] refresh_token 流程不断
- [ ] 撤销(revocation)在两套下都生效

**回滚**: 在 Phase 0.9a 可随时回退,Phase 0.9b 后回退成本高。

**风险**:
- `auth` 模块所有 controller 重写
- 测试覆盖必须 100% (auth 是关键路径)

---

### 0.10 — 决策日志

**问题**: 现有 `sys_audit_log` 只记录 CRUD,不记录**授权决策**(allow/deny)。无法回答"为什么这个用户能/不能访问这个资源"。

**改动**:

1. **新增 Flyway** `V20260920_02__add_sys_decision_log.sql`
   ```sql
   CREATE TABLE sys_decision_log (
       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
       decision_id UUID NOT NULL UNIQUE,
       create_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
       subject_type VARCHAR(32) NOT NULL,  -- 'user' | 'service_account'
       subject_id UUID NOT NULL,
       action VARCHAR(128) NOT NULL,
       resource_type VARCHAR(64),
       resource_id VARCHAR(256),
       context JSONB,
       effect VARCHAR(16) NOT NULL,        -- 'allow' | 'deny'
       reason TEXT,
       policy_version VARCHAR(32),
       request_id VARCHAR(64),
       latency_ms INTEGER NOT NULL,
       source_module VARCHAR(64),          -- 'auth' | 'gateway' | 'system-service'
       -- 月分区
   ) PARTITION BY RANGE (create_time);
   -- 类似 sys_audit_log 创建预分区 + auto-create function
   ```

2. **新增** `common/security-api/.../decision/DecisionRecorder.java`
   - `DecisionRecorder.record(DecisionEvent event) → void`
   - 异步写入 (`@Async` + 批量 flush, 1s 批量或 100 条批量)
   - 失败入死信队列 (Redis Stream)

3. **修改** `common/web/.../security/filter/JwtAuthenticationFilter.java`
   - 写一条 `effect=allow|deny` 决策 (依据 token 验证结果)

4. **修改** `common/web/.../security/filter/StepUpFilter.java`
   - 写 `effect=deny, reason=STEP_UP_REQUIRED`

5. **修改** `CustomPermissionEvaluator`
   - 包一层 try/finally,写决策日志

6. **新增** `system/service/.../controller/SysDecisionLogController.java`
   - `GET /v1/admin/decision-log` (受控,Phase 0 仅 admin 可读)
   - 查询参数: `subject_id`, `action`, `effect`, `from`, `to`,分页

7. **新增** Nacos 配置 `observability.decision-log.batch-size=100`, `flush-interval=1000ms`

   **subject_type 字段说明**:Phase 0 仅使用 `user`;`service_account` 预留,Phase 1 引入 ServiceAccount 后启用。

**数据库**: 新表 `sys_decision_log`,按月分区。

**测试**:
- [ ] 一次成功请求 → 一条 decision_log 行 (effect=allow)
- [ ] 权限被拒 → effect=deny + reason
- [ ] 异步批量: 100 请求 1 秒内,落库 1 次或 2 次
- [ ] Redis 不可达 → 降级为同步写 + 告警 (不丢决策)

**回滚**: 配置 `observability.decision-log.enabled=false`。

---

## 6. 部署顺序与切换

```
D+0   部署 Wave 1 (0.3, 0.4) → 不影响线上
D+3   部署 Wave 2 (0.1, 0.5, 0.6, 0.7, 0.10)
        ├─ 0.6 SysAuditLog 切换需短暂停写 (≤ 5min)
        └─ 0.1 验证默认关闭,配置 enabled=true 后生效
D+10  部署 Wave 3 (0.2, 0.9a) — OAuth2 AS 双签发,旧 token 仍可读
D+30  Wave 3 完成 (0.9b) — 旧 JwtUtils 标记 deprecated
D+60  部署 Wave 4 (0.8) — /v1/ 前缀开启,老路径 Deprecation header
D+270 移除 /v1/ 兼容路径 (Sunset date 到期)
```

---

## 7. 风险登记

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| 0.1 strict mode 导致现存客户端全部 401 | 高 | 高 | 灰度:按 service-name 白名单逐步启用 |
| 0.9 JWT 迁移期 token 解析失败 | 中 | 高 | 0.9a 双格式并行,监控切换率 |
| 0.6 SysAuditLog 合并丢日志 | 中 | 中 | 切换前全量回放 1 天 |
| 0.10 决策日志写库拖垮 DB | 中 | 中 | 异步批量 + Redis Stream 缓冲 |
| 0.5 Dubbo 内部 token TTL 配置错误 → 全员超时 | 低 | 高 | 默认 60s,大集群需测试 |

---

## 8. 验收标准

**功能验收** (每个 PR 必须满足):
- [ ] 单元测试覆盖率 ≥ 80% (CLAUDE.md 要求)
- [ ] 集成测试覆盖核心场景
- [ ] 无新增 lint / spotbugs 警告
- [ ] `mvn test -pl <module>` 全绿
- [ ] PR 描述含: 风险、回滚步骤、监控指标

**Phase 0 完成验收** (所有 10 项合并后):
- [ ] 集成测试: 篡改 `X-User-Id` 不被信任 (0.1)
- [ ] 集成测试: 用户禁用后老 token 被拒 (0.2)
- [ ] 集成测试: 普通用户无法枚举权限 URL (0.3)
- [ ] 集成测试: 硬编码超管 UUID 不再生效,可配置 (0.4)
- [ ] 集成测试: 伪造 Dubbo 调用被拒 (0.5)
- [ ] 集成测试: 审计日志写入路径唯一 (0.6)
- [ ] 集成测试: 审批 type=2 通过后权限生效 (0.7)
- [ ] 集成测试: `/v1/` 与老路径共存 (0.8)
- [ ] 集成测试: OAuth2 AS 签发包含全部原 claim (0.9)
- [ ] 集成测试: 每次 `@PreAuthorize` 评估写入决策日志 (0.10)

**性能验收**:
- [ ] 0.1 验证过滤器 P99 < 0.5ms
- [ ] 0.10 决策日志不影响主链路 P99 (≤ 1ms 增量)
- [ ] 0.5 Dubbo internalToken 验证 P99 < 1ms

---

## 9. 文档交付

每个 PR 必须更新:
- `docs/architecture-review.md` 中对应 P0/P1/P2 状态(✅ / ⏳)
- 新增配置项写入 `docs/` 配置手册
- 公共组件 API 写入对应 README

---

## 10. 下一步

此 spec 经用户审阅通过后,转入 `superpowers:writing-plans` 生成每项的详细任务级实施计划(task-by-task checklist)。
