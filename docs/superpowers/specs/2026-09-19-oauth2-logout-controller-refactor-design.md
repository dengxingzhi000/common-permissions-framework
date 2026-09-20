# OAuth2LogoutController 职责与权限优化 — 设计文档

> **For**: CommonPermissionsFramework (`common-permissions-framework`)
> **Status**: Draft v1 — awaiting user review
> **Module**: `auth`
> **Author**: Backend refactor session
> **Date**: 2026-09-19

---

## 1. 背景与目标

### 1.1 当前状态

`auth/src/main/java/com/frog/auth/controller/OAuth2LogoutController.java:35` 当前的实现存在以下问题:

1. **职责越界** — 控制器内联了 header 解析、token 校验、分支逻辑、存储调用、审计,**85 行中只有 ~12 行是真正的 HTTP 边界代码**。`SysAuthController` 已经走 `ISysAuthService` 分层,本控制器却绕过服务层直接持有 `OAuth2AuthorizationService` 与 `JwtUtils`,与同模块风格不一致。
2. **权限边界过粗** — 整个端点统一使用 `@PreAuthorize("isAuthenticated()")`,不区分"撤销自己的某个客户端会话"与"撤销用户全部 OAuth2 授权"。后者属于管理员操作,不应允许任何已登录用户触发。
3. **`clientId` 参数被忽略** — 参数只作为分支标志(传入即走单客户端、未传入即走全局),从未用于过滤。当前是 bug。
4. **全局分支越权调用** — `OAuth2LogoutController:79` 调用 `jwtUtils.revokeAllUserTokens(userId)` 清理了 `JwtUtils`+Redis 存储,而 `/v1/oauth2/logout` 语义上属于 OAuth2 授权服务器撤销端点,只应清理 `OAuth2AuthorizationService` 存储。
5. **Spring `OAuth2AuthorizationService` 默认实现无"按 userId 查询"** — 标准接口(`InMemoryOAuth2AuthorizationService`)只暴露 `findByToken`/`findById`/`save`/`remove`,全局撤销只能靠遍历或者维护侧索引。
6. **缺少审计** — `SysAuthController.logout()` 与 `forceLogout()` 都通过 `ISysAuditLogService.recordLogout` 写日志,本控制器无审计记录。

### 1.2 目标

| # | 目标 | 验收标准 |
|---|---|---|
| G1 | 控制器只负责 HTTP 边界 | 控制器内不再 `import` `OAuth2AuthorizationService`、`JwtUtils` |
| G2 | 业务逻辑下沉到 `IOAuth2LogoutService` | 新建接口与实现,包含归属校验、审计、存储调用 |
| G3 | 权限分层 | 单客户端撤销 `isAuthenticated()`;全局撤销 `hasAuthority('oauth2:logout:global')` |
| G4 | 引入 `oauth2:logout:global` 权限点 | 权限表 / 初始化脚本注册该权限 |
| G5 | 全局登出真正清理 OAuth2 授权存储 | 通过 Redis 侧索引 + 装饰器模式实现 |
| G6 | 端点拆分为两条路径 | `POST /v1/oauth2/logout`(单客户端)、`POST /v1/oauth2/logout/all`(全局) |
| G7 | 写审计日志 | 单客户端 `riskLevel=2`,全局 `riskLevel=3` |

### 1.3 非目标 (Out of scope)

- 不替换 `OAuth2AuthorizationService` 后端(不引入 JDBC 实现)。
- 不修改 `JwtUtils.revokeAllUserTokens` 语义。
- 不调整 `/api/auth/logout`(`SysAuthController`)接口;它服务于用户名密码登录,与 OAuth2 撤销端点职责分离。
- 不引入多租户隔离增强(Phase 1 范畴)。
- 不修改 OAuth2 授权服务器的 issuer、JWK、registered client 配置(`AuthorizationServerConfig`)。

---

## 2. 架构设计

### 2.1 组件关系

```
HTTP
 │
 ▼
┌────────────────────────────────┐
│ OAuth2LogoutController         │  ← 仅 HTTP + @PreAuthorize
│  (改造为薄控制器)               │
└───────────────┬────────────────┘
                │ 注入
                ▼
┌────────────────────────────────┐
│ IOAuth2LogoutService           │  ← 业务逻辑
│  + OAuth2LogoutServiceImpl     │
└──────┬─────────────┬───────────┘
       │             │
       │             │
       ▼             ▼
┌─────────────────┐  ┌──────────────────────────────┐
│ SideIndexing…   │  │ ISysAuditLogService          │
│ Authorization   │  │ (已有,在 common/log)         │
│ Service (@Prim) │  │                              │
└────────┬────────┘  └──────────────────────────────┘
         │ 委托
         ▼
┌──────────────────────┐         ┌──────────────────┐
│ OAuth2Authorization  │  (默认) │ RedisTemplate    │
│ Service (Spring 默认)│         │ (已有,auth 注入) │
└──────────────────────┘         └──────────────────┘
```

### 2.2 新增 / 改动文件清单

| 文件 | 类型 | 说明 |
|---|---|---|
| `auth/src/main/java/com/frog/auth/service/IOAuth2LogoutService.java` | **新增** | 接口 |
| `auth/src/main/java/com/frog/auth/service/Impl/OAuth2LogoutServiceImpl.java` | **新增** | 实现 |
| `auth/src/main/java/com/frog/auth/security/SideIndexingOAuth2AuthorizationService.java` | **新增** | 装饰器,@Primary |
| `auth/src/main/java/com/frog/auth/controller/OAuth2LogoutController.java` | **改造** | 拆 2 endpoint,薄控制器 |
| `auth/src/test/java/com/frog/auth/service/Impl/OAuth2LogoutServiceImplTest.java` | **新增** | 单元测试 |
| `auth/src/test/java/com/frog/auth/security/SideIndexingOAuth2AuthorizationServiceTest.java` | **新增** | 单元测试 |
| `auth/src/test/java/com/frog/auth/controller/OAuth2LogoutControllerTest.java` | **新增** | `@WebMvcTest` |
| `system/service/src/main/resources/db/migration/V20260919_04__add_oauth2_logout_global_permission.sql` | **新增** | Flyway 迁移脚本(放在 `system/service` 而非 `auth`,沿用项目现有迁移目录约定);注册 `oauth2:logout:global` 权限点并授予 `ROLE_SUPER_ADMIN`(项目实际授予的角色;`RoleDTO` 强制 `^ROLE_[A-Z_]+$`) |

### 2.3 依赖关系

- `OAuth2LogoutServiceImpl` 依赖 `SideIndexingOAuth2AuthorizationService`(而非 `OAuth2AuthorizationService`),因为侧索引版本需要被业务层感知(全局登出时反查索引)。
- `SideIndexingOAuth2AuthorizationService` 实现 `OAuth2AuthorizationService`,委托给 Spring 默认 Bean(`InMemoryOAuth2AuthorizationService`),通过构造函数注入。
- 控制器只依赖 `IOAuth2LogoutService`;**不允许**直接依赖 `OAuth2AuthorizationService` 或 `JwtUtils`。

---

## 3. 权限模型

### 3.1 权限点定义

```
权限编码: oauth2:logout:global
权限名称: OAuth2 全局登出
权限类型: 按钮 / 接口级
适用角色: ROLE_SUPER_ADMIN (项目实际授予角色;`RoleDTO` 强制 `^ROLE_[A-Z_]+$`)
```

### 3.2 注解使用

| 端点 | SpEL | 说明 |
|---|---|---|
| `POST /v1/oauth2/logout` | `@PreAuthorize("isAuthenticated()")` | 调用者必须已登录;归属校验在 service 层 |
| `POST /v1/oauth2/logout/all` | `@PreAuthorize("hasAuthority('oauth2:logout:global')")` | 仅具备该权限的管理员可调用 |

### 3.3 初始化脚本

若使用 SQL 初始化脚本管理权限,新增一条:

```sql
INSERT INTO sys_permission (id, perm_code, perm_name, perm_type, status, created_at, updated_at)
VALUES (<uuid>, 'oauth2:logout:global', 'OAuth2 全局登出', 'button', 1, NOW(), NOW())
ON CONFLICT (perm_code) DO NOTHING;
```

并将该权限授予 `ROLE_SUPER_ADMIN` 角色(根据现有角色-权限关联表结构与 `RoleDTO` 强制 `^ROLE_[A-Z_]+$` 的约定)。

---

## 4. Redis 侧索引设计

### 4.1 数据结构

| Key | 类型 | 含义 | TTL |
|---|---|---|---|
| `oauth2:user:auths:{userId}` | Set\<String authorizationId\> | 该 userId 名下所有 OAuth2 授权 ID | 无,随 save/remove 同步 |

### 4.2 维护时机

由 `SideIndexingOAuth2AuthorizationService` 在以下时机维护:

```java
@Override
public void save(OAuth2Authorization authorization) {
    delegate.save(authorization);
    UUID userId = extractUserId(authorization);   // 从 access_token JWT claim 解析
    if (userId != null) {
        redis.opsForSet().add("oauth2:user:auths:" + userId, authorization.getId());
    }
}

@Override
public void remove(OAuth2Authorization authorization) {
    delegate.remove(authorization);
    UUID userId = extractUserId(authorization);
    if (userId != null) {
        redis.opsForSet().remove("oauth2:user:auths:" + userId, authorization.getId());
    }
    // 同时清理空集合
    Long size = redis.opsForSet().size("oauth2:user:auths:" + userId);
    if (size != null && size == 0) {
        redis.delete("oauth2:user:auths:" + userId);
    }
}
```

### 4.3 userId 解析

```java
private UUID extractUserId(OAuth2Authorization authorization) {
    OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
    if (accessToken == null) return null;
    String tokenValue = accessToken.getToken().getTokenValue();
    try {
        // JwtUtils 已有方法
        return jwtUtils.getUserIdFromToken(tokenValue);
    } catch (Exception ex) {
        log.debug("Cannot extract userId from access token for auth {}", authorization.getId());
        return null;
    }
}
```

> 说明:若授权没有 access_token(如纯 refresh_token 交换、authorization_code 临时态),索引会跳过该记录,后续该 userId 发新 access_token 时再入库。MVP 接受此限制。

### 4.4 冷启动说明

重启前已发放但未刷新的 token,索引为空,全局登出不会清理它们。这是已知的 MVP 限制,通过刷新或重新签发 access_token 后自动入库,后续全局登出可覆盖。

---

## 5. 服务接口设计

### 5.1 `IOAuth2LogoutService`

```java
package com.frog.auth.service;

public interface IOAuth2LogoutService {

    /**
     * 撤销指定 access token 对应的 OAuth2 授权(单客户端)
     *
     * @param accessToken   访问令牌
     * @param clientId      客户端 ID(审计与日志)
     * @param callerUserId  调用者 userId(归属校验)
     * @throws BusinessException 4001 令牌不属于当前用户
     * @throws BusinessException 4004 令牌未找到
     */
    void revokeByClient(String accessToken, String clientId, UUID callerUserId);

    /**
     * 撤销指定用户的所有 OAuth2 授权(全局,需 oauth2:logout:global 权限)
     *
     * @param targetUserId   目标用户 ID
     * @param reason         撤销原因(审计)
     * @param callerUsername 调用者用户名(审计)
     * @return 实际清理的授权条数
     */
    int revokeGlobal(UUID targetUserId, String reason, String callerUsername);
}
```

### 5.2 `OAuth2LogoutServiceImpl`

```java
@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2LogoutServiceImpl implements IOAuth2LogoutService {

    private final OAuth2AuthorizationService authorizationService;   // 注入 @Primary 的 SideIndexing 版本
    private final JwtUtils jwtUtils;                                  // 仅用于解析 token 中的 userId
    private final ISysAuditLogService auditLogService;

    @Override
    public void revokeByClient(String accessToken, String clientId, UUID callerUserId) {
        // 1. 校验 access token 解析得到 userId
        UUID tokenUserId;
        try {
            tokenUserId = jwtUtils.getUserIdFromToken(accessToken);
        } catch (Exception ex) {
            throw new BusinessException(4001, "令牌无效或已过期");
        }

        // 2. 归属校验
        if (!tokenUserId.equals(callerUserId)) {
            throw new BusinessException(4001, "令牌不属于当前用户");
        }

        // 3. 查 OAuth2AuthorizationService
        OAuth2Authorization authorization = authorizationService.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null) {
            throw new BusinessException(4004, "OAuth2 授权未找到");
        }

        // 4. 删除
        authorizationService.remove(authorization);

        // 5. 审计
        auditLogService.recordLogout(callerUserId, "OAuth2 单客户端登出: clientId=" + clientId);
    }

    @Override
    public int revokeGlobal(UUID targetUserId, String reason, String callerUsername) {
        Set<String> authIds = redisTemplate.opsForSet().members("oauth2:user:auths:" + targetUserId);
        if (authIds == null || authIds.isEmpty()) {
            auditLogService.recordLogout(targetUserId, "OAuth2 全局登出(无授权): reason=" + reason);
            return 0;
        }

        int removed = 0;
        for (String authId : authIds) {
            OAuth2Authorization auth = authorizationService.findById(authId);
            if (auth != null) {
                authorizationService.remove(auth);
                removed++;
            }
        }

        // 清理索引 key
        redisTemplate.delete("oauth2:user:auths:" + targetUserId);

        // 审计
        auditLogService.recordLogout(
            targetUserId,
            String.format("OAuth2 全局登出: count=%d, reason=%s, operator=%s",
                    removed, reason, callerUsername));

        return removed;
    }
}
```

---

## 6. 控制器改造

### 6.1 端点拆分

| 端点 | 路径 | 注解 | 入参 | 出参 |
|---|---|---|---|---|
| 单客户端撤销 | `POST /v1/oauth2/logout` | `@PreAuthorize("isAuthenticated()")` | `@RequestHeader("Authorization") String authHeader`<br>`@RequestParam("clientId") @NotBlank String clientId` | `ApiResults<Void>` |
| 全局登出 | `POST /v1/oauth2/logout/all` | `@PreAuthorize("hasAuthority('oauth2:logout:global')")` | `@AuthenticationPrincipal SecurityUser caller`<br>`@RequestParam("reason") @NotBlank String reason` | `ApiResults<Integer>` (清理条数) |

### 6.2 控制器代码骨架

```java
@Slf4j
@Validated
@RestController
@RequestMapping("/v1/oauth2")
@RequiredArgsConstructor
@Tag(name = "OAuth2 登出", description = "OAuth2 授权撤销管理")
public class OAuth2LogoutController {

    private final IOAuth2LogoutService oauth2LogoutService;
    private final HttpServletRequestUtils httpServletRequestUtils;

    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    @AuditLog(operation = "OAuth2 单客户端登出", businessType = "USER", riskLevel = 2)
    public ApiResults<Void> revokeByClient(
            HttpServletRequest request,
            @RequestParam("clientId") @NotBlank String clientId,
            @AuthenticationPrincipal SecurityUser caller) {

        String accessToken = httpServletRequestUtils.getTokenFromRequest(request);
        if (!StringUtils.hasText(accessToken)) {
            return ApiResults.fail(400, "Authorization 头格式无效");
        }

        oauth2LogoutService.revokeByClient(accessToken, clientId, caller.getUserId());
        return ApiResults.success();
    }

    @PostMapping("/logout/all")
    @PreAuthorize("hasAuthority('oauth2:logout:global')")
    @AuditLog(operation = "OAuth2 全局登出", businessType = "USER", riskLevel = 3)
    public ApiResults<Integer> revokeGlobal(
            @RequestParam("userId") UUID userId,
            @RequestParam("reason") @NotBlank String reason,
            @AuthenticationPrincipal SecurityUser caller) {

        int removed = oauth2LogoutService.revokeGlobal(userId, reason, caller.getUsername());
        return ApiResults.success(removed);
    }
}
```

### 6.3 关键变化

- **不再** import `OAuth2AuthorizationService`、`JwtUtils`、`OAuth2TokenType`、`UUID`(除 `@RequestParam` 用)。
- 使用 `HttpServletRequestUtils.getTokenFromHeader()` 替代手写的 `Bearer ` 前缀剥离(已在 `common/web`)。
- 使用 `@AuthenticationPrincipal SecurityUser` 替代手动 `jwtUtils.getUserIdFromToken` 重复解析。
- `clientId` 升级为 `@NotBlank` 必填参数,移除"用是否传入区分分支"的反模式。
- 单客户端登出新增 `@AuditLog(riskLevel=2)`,全局登出 `@AuditLog(riskLevel=3)`(均在 `common/log` 提供的 `@AuditLog` 注解中声明;满足 G7 风险等级要求)。

---

## 7. 装饰器:SideIndexingOAuth2AuthorizationService

### 7.1 Bean 装配

```java
@Configuration
public class OAuth2AuthorizationServiceConfig {

    @Bean
    @Primary
    public SideIndexingOAuth2AuthorizationService sideIndexingOAuth2AuthorizationService(
            @Qualifier("inMemoryOAuth2AuthorizationService") OAuth2AuthorizationService delegate,
            RedisTemplate<String, String> redisTemplate,
            JwtUtils jwtUtils) {

        return new SideIndexingOAuth2AuthorizationService(delegate, redisTemplate, jwtUtils);
    }
}
```

> **风险**:Spring Boot 自动配置提供的 Bean 名称在不同版本可能不同,需要确认实际 Bean 名称。若无法用 `@Qualifier` 注入,改为禁用 `OAuth2AuthorizationServerAutoConfiguration` 并显式声明委托 Bean。

### 7.2 类骨架

```java
@Service
@Primary
@Slf4j
public class SideIndexingOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final OAuth2AuthorizationService delegate;
    private final RedisTemplate<String, String> redisTemplate;
    private final JwtUtils jwtUtils;

    private static final String INDEX_KEY_PREFIX = "oauth2:user:auths:";

    public SideIndexingOAuth2AuthorizationService(
            OAuth2AuthorizationService delegate,
            RedisTemplate<String, String> redisTemplate,
            JwtUtils jwtUtils) {
        this.delegate = delegate;
        this.redisTemplate = redisTemplate;
        this.jwtUtils = jwtUtils;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        delegate.save(authorization);
        addToIndex(authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
        removeFromIndex(authorization);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        return delegate.findByToken(token, tokenType);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }

    private void addToIndex(OAuth2Authorization authorization) {
        UUID userId = extractUserId(authorization);
        if (userId == null) return;
        redisTemplate.opsForSet().add(INDEX_KEY_PREFIX + userId, authorization.getId());
    }

    private void removeFromIndex(OAuth2Authorization authorization) {
        UUID userId = extractUserId(authorization);
        if (userId == null) return;
        String key = INDEX_KEY_PREFIX + userId;
        redisTemplate.opsForSet().remove(key, authorization.getId());
        Long size = redisTemplate.opsForSet().size(key);
        if (size != null && size == 0L) {
            redisTemplate.delete(key);
        }
    }

    private UUID extractUserId(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
        if (accessToken == null) return null;
        try {
            return jwtUtils.getUserIdFromToken(accessToken.getToken().getTokenValue());
        } catch (Exception ex) {
            return null;
        }
    }
}
```

### 7.3 RedisTemplate 类型

auth 模块当前注入的 `RedisTemplate` 类型需确认(在 `SysAuthServiceImpl` 中是 `RedisTemplate<String, Object>`)。装饰器需要 `RedisTemplate<String, String>`,若未单独声明 `RedisTemplate<String, String>` Bean,需要新增或做类型适配。

---

## 8. 错误处理

| 场景 | 抛出 / 返回 | HTTP 状态 / 业务码 |
|---|---|---|
| 单客户端:Authorization 头无效 | `ApiResults.fail(400, "...")` | 200 + 业务码 400 |
| 单客户端:token 解析失败 | `BusinessException(4001, "令牌无效或已过期")` | 由全局异常处理器映射 |
| 单客户端:token 不归属当前用户 | `BusinessException(4001, "令牌不属于当前用户")` | 同上 |
| 单客户端:OAuth2 授权未找到 | `BusinessException(4004, "OAuth2 授权未找到")` | 同上 |
| 全局:`@PreAuthorize` 失败 | Spring Security 默认 403 | 403 |
| 全局:索引为空 | `ApiResults.success(0)` | 200 + 0 |

所有 `BusinessException` 经由 `common/web` 的全局异常处理器统一处理,前端得到一致的 JSON 结构。

---

## 9. 测试策略

### 9.1 单元测试(本地可跑,CI 不门禁)

| 类 | 覆盖点 |
|---|---|
| `OAuth2LogoutServiceImplTest` | 归属校验失败抛 4001;token 无效抛 4001;授权未找到抛 4004;正常删除 + 审计调用;全局分支统计清理条数 + 审计 |
| `SideIndexingOAuth2AuthorizationServiceTest` | save 后索引含;remove 后索引不含;空索引清理;无 access_token 时跳过 |
| `OAuth2LogoutControllerTest` | `@WebMvcTest` + `@WithMockUser`:两条路径分别测试 SpEL 通过;mock service 校验参数透传 |

### 9.2 集成测试(可选,需启动 Redis)

未在本 spec 范围内,但建议在 `auth` 模块 CI 容器化后补一个 `@SpringBootTest` 用 Testcontainers 跑端到端。

### 9.3 手动验收

1. 用 password grant 拿 access_token → `POST /v1/oauth2/logout?clientId=internal-service` → 期望 200 + Redis 索引 -1 + 审计日志 1 条。
2. 用同一 access_token 调任意受保护接口 → 期望 401。
3. 用 user A 的 token + user B 的 session → `POST /v1/oauth2/logout?clientId=...` → 期望 4001。
4. 用管理员账号(`oauth2:logout:global` 权限)调 `POST /v1/oauth2/logout/all?userId=A&reason=test` → 期望 200 + 返回条数。
5. 用非管理员账号调全局端点 → 期望 403。

---

## 10. 迁移 / 部署

### 10.1 顺序

1. 数据库迁移:注册 `oauth2:logout:global` 权限点(脚本位于 `system/service/src/main/resources/db/migration/`,沿用项目现有 Flyway 迁移目录;脚本可与本次代码变更一同发布,但权限点独立可灰度)。
2. 代码部署:本次重构在单次提交内完成,无需灰度(接口路径对外保持兼容 —— 旧的 `POST /v1/oauth2/logout?clientId=X` 仍是单客户端路径)。
3. **旧调用方兼容**:本次保留 `POST /v1/oauth2/logout` 单客户端路径,仅当 `clientId` 缺省时返回 400(因为新规则下 clientId 必填);全局部署前需确认前端已升级。

### 10.2 风险

| 风险 | 缓解 |
|---|---|
| `@Primary` 装饰器 Bean 装配失败导致 `OAuth2AuthorizationService` 多实例 | 启动时 `@PostConstruct` 日志校验代理链;失败则 fail-fast |
| `RedisTemplate<String, String>` 未声明导致注入失败 | 若 `RedisTemplate<String, Object>` 是唯一 Bean,装饰器内自行 cast 或新声明 |
| 冷启动数据:旧授权不在索引里 | 已记录 MVP 限制,提示运维刷新 token |
| 旧的 `POST /v1/oauth2/logout` 不传 clientId 会被拒 | 在前端升级前,灰度期间可临时允许空 clientId 等价于"全端点"分支,本次不做兼容 |

---

## 11. 与现有规范的一致性

- 包命名 `com.frog.auth.{controller,service,security}` 与既有约定一致。
- 使用 Lombok `@Slf4j` `@RequiredArgsConstructor` 不手写 getter。
- 使用既有 `ApiResults`、`HttpServletRequestUtils`、`ISysAuditLogService`、`@AuditLog`、`@PreAuthorize`、`@AuthenticationPrincipal`,无新基础设施。
- 测试类遵循既有 `*Test.java` 命名。
- 不修改 `common/*` 模块;所有变更位于 `auth/`。
- 遵循 `AGENTS.md` "Test-dep gotcha":`auth/pom.xml` 已声明 `spring-boot-starter-test` 测试作用域。

---

## 12. 已知遗留

| 项 | 说明 | 后续 |
|---|---|---|
| `OAuth2LogoutServiceImpl.revokeGlobal` 中 `redisTemplate` 字段需在实现内显式注入 | 设计稿已列 | 实施时确认 |
| 冷启动索引空 | MVP 限制 | 后续可改为 `JdbcOAuth2AuthorizationService` 或定时回填脚本 |
| 旧 `clientId` 缺省语义被破坏 | 与前端同步升级 | 在前端升级前,服务端可临时不强制 `@NotBlank`,本次不引入兼容开关 |

---

## 13. 实施步骤概要(交给 writing-plans 细化)

1. 新增 `IOAuth2LogoutService` 接口
2. 新增 `SideIndexingOAuth2AuthorizationService` 装饰器
3. 新增 `OAuth2AuthorizationServiceConfig`(`@Primary` Bean 装配)
4. 新增 `OAuth2LogoutServiceImpl` 实现
5. 改造 `OAuth2LogoutController`(拆 2 endpoint)
6. 数据库初始化脚本新增 `oauth2:logout:global` 权限点
7. 单元测试:服务 / 装饰器 / 控制器
8. 本地 `mvn test -pl auth -am` 通过