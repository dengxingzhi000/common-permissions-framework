# OAuth2LogoutController 职责与权限优化 — 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor `OAuth2LogoutController` into a thin HTTP layer that delegates to a new `IOAuth2LogoutService`, tighten `@PreAuthorize` so single-client revocation is `isAuthenticated()` and global revocation requires a new `oauth2:logout:global` authority, and add a Redis side-index so global revocation actually clears the OAuth2 authorization store (not JwtUtils).

**Architecture:**
- `OAuth2LogoutController` (thin) → `IOAuth2LogoutService` (logic) → `SideIndexingOAuth2AuthorizationService` (`@Primary` decorator over Spring default `InMemoryOAuth2AuthorizationService`) + `ISysAuditLogService`.
- Single endpoint becomes two: `POST /oauth2/logout?clientId=X` and `POST /oauth2/logout/all?userId=Y&reason=Z`.
- Redis side-index `oauth2:user:auths:{userId}` (Set<String authorizationId>) maintained in `save/remove`.

**Tech Stack:** Spring Boot 4, Spring Security OAuth2 Authorization Server, Spring Data Redis (`StringRedisTemplate`), JUnit 5, Mockito, Spring Security Test (`@WithMockUser`), Lombok, MapStruct-free.

---

## File Structure

Created:
- `auth/src/main/java/com/frog/auth/service/IOAuth2LogoutService.java` — interface
- `auth/src/main/java/com/frog/auth/service/Impl/OAuth2LogoutServiceImpl.java` — service impl
- `auth/src/main/java/com/frog/auth/security/SideIndexingOAuth2AuthorizationService.java` — `@Primary` decorator
- `auth/src/main/java/com/frog/auth/security/OAuth2AuthorizationServiceConfig.java` — wires `@Primary` bean
- `auth/src/test/java/com/frog/auth/service/Impl/OAuth2LogoutServiceImplTest.java` — service unit tests
- `auth/src/test/java/com/frog/auth/security/SideIndexingOAuth2AuthorizationServiceTest.java` — decorator unit tests
- `auth/src/test/java/com/frog/auth/controller/OAuth2LogoutControllerTest.java` — `@WebMvcTest` controller tests
- `auth/src/main/resources/db/migration/V20260919_01__add_oauth2_logout_global_permission.sql` — Flyway permission init

Modified:
- `auth/src/main/java/com/frog/auth/controller/OAuth2LogoutController.java` — split 2 endpoints, thin layer

---

## Task 1: Add Flyway migration for `oauth2:logout:global` permission

**Files:**
- Create: `auth/src/main/resources/db/migration/V20260919_01__add_oauth2_logout_global_permission.sql`

- [ ] **Step 1: Verify existing Flyway structure**

Run from repo root:

```bash
Test-Path "auth/src/main/resources/db/migration"  # pwsh
ls auth/src/main/resources/db/migration | head -20
```

Expected: directory exists; existing migration files named `V*.sql`.

- [ ] **Step 2: Create the migration SQL file**

Write `auth/src/main/resources/db/migration/V20260919_01__add_oauth2_logout_global_permission.sql`:

```sql
-- 注册 OAuth2 全局登出权限点
INSERT INTO sys_permission (id, perm_code, perm_name, perm_type, status, created_at, updated_at, deleted)
VALUES ('019a0aee-3b74-7bfc-b34f-48b5428d48aa', 'oauth2:logout:global', 'OAuth2 全局登出', 'button', 1, NOW(), NOW(), 0)
ON CONFLICT (perm_code) DO NOTHING;

-- 授权给 ROLE_ADMIN（按现有 sys_role / sys_role_permission 关联表结构调整）
INSERT INTO sys_role_permission (id, role_id, permission_id, created_at, deleted)
SELECT '019a0aee-3b74-7bfc-b34f-48b5428d48ab', r.id, p.id, NOW(), 0
FROM sys_role r, sys_permission p
WHERE r.role_code = 'ROLE_ADMIN' AND p.perm_code = 'oauth2:logout:global'
ON CONFLICT DO NOTHING;
```

- [ ] **Step 3: Confirm table/column names**

If `sys_permission` / `sys_role_permission` columns differ from above (e.g. `perm_code` vs `permission_code`, `role_code` vs `code`), adjust the SQL to match the actual DDL. Do not invent columns. Use:

```bash
grep -r "sys_permission" --include="*.sql" --include="*.java" -l auth/ system/
```

to find authoritative schema.

- [ ] **Step 4: Commit**

```bash
git add "auth/src/main/resources/db/migration/V20260919_01__add_oauth2_logout_global_permission.sql"
git commit -m "feat(auth): 注册 oauth2:logout:global 权限点"
```

---

## Task 2: Define `IOAuth2LogoutService` interface

**Files:**
- Create: `auth/src/main/java/com/frog/auth/service/IOAuth2LogoutService.java`

- [ ] **Step 1: Create the interface**

Write `auth/src/main/java/com/frog/auth/service/IOAuth2LogoutService.java`:

```java
package com.frog.auth.service;

import java.util.UUID;

/**
 * OAuth2 授权撤销服务接口
 *
 * <p>仅操作 {@code OAuth2AuthorizationService} 存储,不触碰 {@code JwtUtils}。
 * 单客户端撤销由调用方持有 access token 即可触发;全局撤销需上层授予
 * {@code oauth2:logout:global} 权限。</p>
 *
 * @since 2026-09-19
 */
public interface IOAuth2LogoutService {

    /**
     * 撤销指定 access token 对应的 OAuth2 授权(单客户端)
     *
     * @param accessToken  访问令牌
     * @param clientId     客户端 ID(仅用于审计日志)
     * @param callerUserId 调用者 userId(归属校验)
     * @throws com.frog.common.exception.BusinessException 4001 token 解析失败或不归属当前用户
     * @throws com.frog.common.exception.BusinessException 4004 OAuth2 授权未找到
     */
    void revokeByClient(String accessToken, String clientId, UUID callerUserId);

    /**
     * 撤销指定用户的所有 OAuth2 授权(全局,需 {@code oauth2:logout:global} 权限)
     *
     * @param targetUserId   目标用户 ID
     * @param reason         撤销原因
     * @param callerUsername 调用者用户名(审计)
     * @return 实际清理的授权条数
     */
    int revokeGlobal(UUID targetUserId, String reason, String callerUsername);
}
```

- [ ] **Step 2: Compile the module**

Run from repo root:

```bash
mvn -pl auth -am compile -q
```

Expected: `BUILD SUCCESS`.

- [ ] **Step 3: Commit**

```bash
git add auth/src/main/java/com/frog/auth/service/IOAuth2LogoutService.java
git commit -m "feat(auth): 新增 IOAuth2LogoutService 接口"
```

---

## Task 3: TDD `OAuth2LogoutServiceImpl.revokeByClient`

**Files:**
- Create: `auth/src/test/java/com/frog/auth/service/Impl/OAuth2LogoutServiceImplTest.java`
- Create: `auth/src/main/java/com/frog/auth/service/Impl/OAuth2LogoutServiceImpl.java`

- [ ] **Step 1: Write failing tests**

Write `auth/src/test/java/com/frog/auth/service/Impl/OAuth2LogoutServiceImplTest.java`:

```java
package com.frog.auth.service.Impl;

import com.frog.auth.security.SideIndexingOAuth2AuthorizationService;
import com.frog.common.exception.BusinessException;
import com.frog.common.log.service.ISysAuditLogService;
import com.frog.common.security.util.JwtUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OAuth2LogoutServiceImplTest {

    @Mock OAuth2AuthorizationService authorizationService;
    @Mock JwtUtils jwtUtils;
    @Mock ISysAuditLogService auditLogService;
    @Mock StringRedisTemplate redisTemplate;

    @InjectMocks OAuth2LogoutServiceImpl service;

    private final UUID callerUserId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a1");
    private final String accessToken = "valid.jwt.token";
    private final String clientId = "internal-service";

    @Test
    void revokeByClient_happyPath_removesAuthorizationAndAudits() {
        when(jwtUtils.getUserIdFromToken(accessToken)).thenReturn(callerUserId);
        OAuth2Authorization auth = OAuth2Authorization.withRegisteredClient(
                RegisteredClient.withId("client-1")
                        .clientId(clientId)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .build())
                .principalName("alice")
                .build();
        when(authorizationService.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN))
                .thenReturn(auth);

        service.revokeByClient(accessToken, clientId, callerUserId);

        verify(authorizationService).remove(auth);
        verify(auditLogService).recordLogout(eq(callerUserId), anyString());
    }

    @Test
    void revokeByClient_tokenUserIdMismatch_throws4001() {
        UUID otherUser = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a2");
        when(jwtUtils.getUserIdFromToken(accessToken)).thenReturn(otherUser);

        assertThatThrownBy(() -> service.revokeByClient(accessToken, clientId, callerUserId))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("不属于当前用户");

        verify(authorizationService, never()).remove(any());
        verify(auditLogService, never()).recordLogout(any(), any());
    }

    @Test
    void revokeByClient_tokenInvalid_throws4001() {
        when(jwtUtils.getUserIdFromToken(accessToken))
                .thenThrow(new IllegalArgumentException("bad token"));

        assertThatThrownBy(() -> service.revokeByClient(accessToken, clientId, callerUserId))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("令牌无效");
    }

    @Test
    void revokeByClient_authorizationNotFound_throws4004() {
        when(jwtUtils.getUserIdFromToken(accessToken)).thenReturn(callerUserId);
        when(authorizationService.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN))
                .thenReturn(null);

        assertThatThrownBy(() -> service.revokeByClient(accessToken, clientId, callerUserId))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("未找到");
    }
}
```

- [ ] **Step 2: Run tests — verify failure (compilation)**

```bash
mvn -pl auth test -Dtest=OAuth2LogoutServiceImplTest -q
```

Expected: compile failure (impl + decorator don't exist yet).

- [ ] **Step 3: Create minimal `SideIndexingOAuth2AuthorizationService` stub**

Write `auth/src/main/java/com/frog/auth/security/SideIndexingOAuth2AuthorizationService.java` with a no-op impl that delegates everything:

```java
package com.frog.auth.security;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

/**
 * Side-indexing decorator — stub created in Task 3, fully implemented in Task 5.
 */
public class SideIndexingOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final OAuth2AuthorizationService delegate;

    public SideIndexingOAuth2AuthorizationService(OAuth2AuthorizationService delegate) {
        this.delegate = delegate;
    }

    @Override public void save(OAuth2Authorization authorization) { delegate.save(authorization); }
    @Override public void remove(OAuth2Authorization authorization) { delegate.remove(authorization); }
    @Override public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) { return delegate.findByToken(token, tokenType); }
    @Override public OAuth2Authorization findById(String id) { return delegate.findById(id); }
}
```

- [ ] **Step 4: Create `OAuth2LogoutServiceImpl` minimal impl**

Write `auth/src/main/java/com/frog/auth/service/Impl/OAuth2LogoutServiceImpl.java`:

```java
package com.frog.auth.service.Impl;

import com.frog.auth.service.IOAuth2LogoutService;
import com.frog.common.exception.BusinessException;
import com.frog.common.log.service.ISysAuditLogService;
import com.frog.common.security.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2LogoutServiceImpl implements IOAuth2LogoutService {

    private final OAuth2AuthorizationService authorizationService;
    private final JwtUtils jwtUtils;
    private final ISysAuditLogService auditLogService;

    @Override
    public void revokeByClient(String accessToken, String clientId, UUID callerUserId) {
        UUID tokenUserId;
        try {
            tokenUserId = jwtUtils.getUserIdFromToken(accessToken);
        } catch (Exception ex) {
            throw new BusinessException(4001, "令牌无效或已过期");
        }
        if (!tokenUserId.equals(callerUserId)) {
            throw new BusinessException(4001, "令牌不属于当前用户");
        }
        OAuth2Authorization authorization = authorizationService.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null) {
            throw new BusinessException(4004, "OAuth2 授权未找到");
        }
        authorizationService.remove(authorization);
        auditLogService.recordLogout(callerUserId, "OAuth2 单客户端登出: clientId=" + clientId);
        log.info("OAuth2 single-client revocation: userId={} clientId={}", callerUserId, clientId);
    }

    @Override
    public int revokeGlobal(UUID targetUserId, String reason, String callerUsername) {
        return 0;
    }
}
```

- [ ] **Step 5: Run tests — verify pass**

```bash
mvn -pl auth test -Dtest=OAuth2LogoutServiceImplTest -q
```

Expected: `Tests run: 4, Failures: 0, Errors: 0, Skipped: 0`.

- [ ] **Step 6: Commit**

```bash
git add auth/src/test/java/com/frog/auth/service/Impl/OAuth2LogoutServiceImplTest.java \
        auth/src/main/java/com/frog/auth/service/Impl/OAuth2LogoutServiceImpl.java \
        auth/src/main/java/com/frog/auth/security/SideIndexingOAuth2AuthorizationService.java
git commit -m "feat(auth): 实现 OAuth2LogoutServiceImpl.revokeByClient"
```

---

## Task 4: TDD `OAuth2LogoutServiceImpl.revokeGlobal`

**Files:**
- Modify: `auth/src/test/java/com/frog/auth/service/Impl/OAuth2LogoutServiceImplTest.java`
- Modify: `auth/src/main/java/com/frog/auth/service/Impl/OAuth2LogoutServiceImpl.java`

- [ ] **Step 1: Add failing tests for `revokeGlobal`**

Append to `OAuth2LogoutServiceImplTest.java`:

```java
import org.springframework.data.redis.core.SetOperations;

import java.util.Set;

import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class OAuth2LogoutServiceImplTest {
    // ... existing fields ...

    @Test
    void revokeGlobal_emptyIndex_returnsZeroAndAudits() {
        SetOperations<String, String> setOps = mock(SetOperations.class);
        when(redisTemplate.opsForSet()).thenReturn(setOps);
        when(setOps.members("oauth2:user:auths:" + callerUserId)).thenReturn(Set.of());

        int removed = service.revokeGlobal(callerUserId, "test", "admin");

        assertThat(removed).isEqualTo(0);
        verify(auditLogService).recordLogout(eq(callerUserId), anyString());
        verify(authorizationService, never()).remove(any());
    }

    @Test
    void revokeGlobal_withAuthorizations_removesAllAndAuditsCount() {
        SetOperations<String, String> setOps = mock(SetOperations.class);
        when(redisTemplate.opsForSet()).thenReturn(setOps);
        Set<String> authIds = Set.of("auth-1", "auth-2");
        when(setOps.members("oauth2:user:auths:" + callerUserId)).thenReturn(authIds);

        OAuth2Authorization a1 = OAuth2Authorization.withRegisteredClient(
                RegisteredClient.withId("c").clientId("x").authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build())
                .principalName("alice").build();
        OAuth2Authorization a2 = OAuth2Authorization.withRegisteredClient(
                RegisteredClient.withId("c").clientId("y").authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build())
                .principalName("alice").build();
        when(authorizationService.findById("auth-1")).thenReturn(a1);
        when(authorizationService.findById("auth-2")).thenReturn(a2);

        int removed = service.revokeGlobal(callerUserId, "compromised account", "admin");

        assertThat(removed).isEqualTo(2);
        verify(authorizationService).remove(a1);
        verify(authorizationService).remove(a2);
        verify(redisTemplate).delete("oauth2:user:auths:" + callerUserId);
        verify(auditLogService).recordLogout(eq(callerUserId), anyString());
    }
```

Add the static import to the top of the test class:

```java
import static org.assertj.core.api.Assertions.assertThat;
```

- [ ] **Step 2: Run tests — verify failure**

```bash
mvn -pl auth test -Dtest=OAuth2LogoutServiceImplTest#revokeGlobal_emptyIndex_returnsZeroAndAudits -q
mvn -pl auth test -Dtest=OAuth2LogoutServiceImplTest#revokeGlobal_withAuthorizations_removesAllAndAuditsCount -q
```

Expected: both FAIL with `Wanted but not invoked: ... recordLogout` or similar.

- [ ] **Step 3: Implement `revokeGlobal`**

Replace the stub `revokeGlobal` in `OAuth2LogoutServiceImpl.java` with:

```java
    @Override
    public int revokeGlobal(UUID targetUserId, String reason, String callerUsername) {
        String key = "oauth2:user:auths:" + targetUserId;
        java.util.Set<String> authIds = redisTemplate.opsForSet().members(key);
        if (authIds == null || authIds.isEmpty()) {
            auditLogService.recordLogout(targetUserId, "OAuth2 全局登出(无授权): reason=" + reason);
            log.info("OAuth2 global revocation: userId={} (no authorizations)", targetUserId);
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
        redisTemplate.delete(key);
        auditLogService.recordLogout(targetUserId,
                String.format("OAuth2 全局登出: count=%d, reason=%s, operator=%s",
                        removed, reason, callerUsername));
        log.info("OAuth2 global revocation: userId={} count={} operator={}", targetUserId, removed, callerUsername);
        return removed;
    }
```

Add field at top of class:

```java
    private final org.springframework.data.redis.core.StringRedisTemplate redisTemplate;
```

(Already added via `@RequiredArgsConstructor` once declared.)

- [ ] **Step 4: Run all service tests — verify pass**

```bash
mvn -pl auth test -Dtest=OAuth2LogoutServiceImplTest -q
```

Expected: `Tests run: 6, Failures: 0, Errors: 0, Skipped: 0`.

- [ ] **Step 5: Commit**

```bash
git add auth/src/test/java/com/frog/auth/service/Impl/OAuth2LogoutServiceImplTest.java \
        auth/src/main/java/com/frog/auth/service/Impl/OAuth2LogoutServiceImpl.java
git commit -m "feat(auth): 实现 OAuth2LogoutServiceImpl.revokeGlobal"
```

---

## Task 5: TDD `SideIndexingOAuth2AuthorizationService`

**Files:**
- Create: `auth/src/test/java/com/frog/auth/security/SideIndexingOAuth2AuthorizationServiceTest.java`
- Modify: `auth/src/main/java/com/frog/auth/security/SideIndexingOAuth2AuthorizationService.java`

- [ ] **Step 1: Write failing tests**

Write `auth/src/test/java/com/frog/auth/security/SideIndexingOAuth2AuthorizationServiceTest.java`:

```java
package com.frog.auth.security;

import com.frog.common.security.util.JwtUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SideIndexingOAuth2AuthorizationServiceTest {

    @Mock OAuth2AuthorizationService delegate;
    @Mock StringRedisTemplate redisTemplate;
    @Mock JwtUtils jwtUtils;

    SideIndexingOAuth2AuthorizationService service;

    private final UUID userId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a1");

    @BeforeEach
    void setUp() {
        service = new SideIndexingOAuth2AuthorizationService(delegate, redisTemplate, jwtUtils);
    }

    private OAuth2Authorization authWithAccessToken(String authId, String accessToken) {
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(
                org.springframework.security.oauth2.server.authorization.client.RegisteredClient.withId("client")
                        .clientId("internal").authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build())
                .principalName("alice")
                .id(authId);
        builder.accessToken(new OAuth2Authorization.Token<>(
                new org.springframework.security.oauth2.core.OAuth2AccessToken(
                        org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER,
                        accessToken,
                        java.time.Instant.now(),
                        java.time.Instant.now().plusSeconds(3600)),
                java.time.Instant.now(),
                java.time.Instant.now().plusSeconds(3600)));
        return builder.build();
    }

    @Test
    void save_addsAuthorizationIdToUserIndex() {
        OAuth2Authorization auth = authWithAccessToken("auth-1", "jwt.token.value");
        when(jwtUtils.getUserIdFromToken("jwt.token.value")).thenReturn(userId);
        SetOperations<String, String> setOps = mock(SetOperations.class);
        when(redisTemplate.opsForSet()).thenReturn(setOps);

        service.save(auth);

        verify(delegate).save(auth);
        verify(setOps).add("oauth2:user:auths:" + userId, "auth-1");
    }

    @Test
    void save_withoutAccessToken_skipsIndexUpdate() {
        OAuth2Authorization auth = OAuth2Authorization.withRegisteredClient(
                org.springframework.security.oauth2.server.authorization.client.RegisteredClient.withId("c")
                        .clientId("x").authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build())
                .principalName("alice").id("auth-2").build();

        service.save(auth);

        verify(delegate).save(auth);
        verify(redisTemplate, never()).opsForSet();
    }

    @Test
    void remove_decrementsIndexAndDeletesEmptyKey() {
        OAuth2Authorization auth = authWithAccessToken("auth-1", "jwt.token.value");
        when(jwtUtils.getUserIdFromToken("jwt.token.value")).thenReturn(userId);
        SetOperations<String, String> setOps = mock(SetOperations.class);
        when(redisTemplate.opsForSet()).thenReturn(setOps);
        when(setOps.size("oauth2:user:auths:" + userId)).thenReturn(0L);

        service.remove(auth);

        verify(delegate).remove(auth);
        verify(setOps).remove("oauth2:user:auths:" + userId, "auth-1");
        verify(setOps).size("oauth2:user:auths:" + userId);
        verify(redisTemplate).delete("oauth2:user:auths:" + userId);
    }

    @Test
    void findByToken_andFindById_passThrough() {
        OAuth2Authorization auth = authWithAccessToken("auth-1", "jwt.token.value");
        when(delegate.findByToken("t", org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN))
                .thenReturn(auth);
        when(delegate.findById("auth-1")).thenReturn(auth);

        assertThat(service.findByToken("t", org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN))
                .isSameAs(auth);
        assertThat(service.findById("auth-1")).isSameAs(auth);
    }
}
```

- [ ] **Step 2: Run tests — verify failure**

```bash
mvn -pl auth test -Dtest=SideIndexingOAuth2AuthorizationServiceTest -q
```

Expected: compile failure (decorator has wrong constructor signature from Task 3 stub).

- [ ] **Step 3: Replace decorator stub with full impl**

Replace `auth/src/main/java/com/frog/auth/security/SideIndexingOAuth2AuthorizationService.java`:

```java
package com.frog.auth.security;

import com.frog.common.security.util.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * 装饰器:在 Spring 默认 {@link OAuth2AuthorizationService} 之上维护 Redis 侧索引
 * <p>索引 key: <code>oauth2:user:auths:{userId}</code> -> Set&lt;String authorizationId&gt;</p>
 * <p>用途:全局登出时按 userId 反查该用户所有 OAuth2 授权 ID,逐条删除。</p>
 *
 * @since 2026-09-19
 */
@Slf4j
@Service
public class SideIndexingOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final String INDEX_KEY_PREFIX = "oauth2:user:auths:";

    private final OAuth2AuthorizationService delegate;
    private final StringRedisTemplate redisTemplate;
    private final JwtUtils jwtUtils;

    public SideIndexingOAuth2AuthorizationService(
            OAuth2AuthorizationService delegate,
            StringRedisTemplate redisTemplate,
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
        String key = INDEX_KEY_PREFIX + userId;
        redisTemplate.opsForSet().add(key, authorization.getId());
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
            log.debug("Cannot extract userId from access token for auth {}", authorization.getId());
            return null;
        }
    }
}
```

- [ ] **Step 4: Run tests — verify pass**

```bash
mvn -pl auth test -Dtest=SideIndexingOAuth2AuthorizationServiceTest -q
```

Expected: `Tests run: 4, Failures: 0, Errors: 0, Skipped: 0`.

- [ ] **Step 5: Commit**

```bash
git add auth/src/test/java/com/frog/auth/security/SideIndexingOAuth2AuthorizationServiceTest.java \
        auth/src/main/java/com/frog/auth/security/SideIndexingOAuth2AuthorizationService.java
git commit -m "feat(auth): 实现 SideIndexingOAuth2AuthorizationService 装饰器"
```

---

## Task 6: Wire `@Primary` decorator as a Spring bean

**Files:**
- Create: `auth/src/main/java/com/frog/auth/security/OAuth2AuthorizationServiceConfig.java`

- [ ] **Step 1: Verify the default `OAuth2AuthorizationService` bean name**

Run from repo root:

```bash
Test-Path "auth/src/main/resources/application.yml"
```

Open the file and look for any explicit `OAuth2AuthorizationService` bean override. The expectation: none — Spring Boot's `OAuth2AuthorizationServerAutoConfiguration` provides an `InMemoryOAuth2AuthorizationService` bean named `inMemoryOAuth2AuthorizationService`. If you find a different name, adjust Step 2 accordingly.

- [ ] **Step 2: Create the config class**

Write `auth/src/main/java/com/frog/auth/security/OAuth2AuthorizationServiceConfig.java`:

```java
package com.frog.auth.security;

import com.frog.common.security.util.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

/**
 * 用 {@link SideIndexingOAuth2AuthorizationService} 装饰 Spring Boot 自动配置的
 * {@code InMemoryOAuth2AuthorizationService},作为主 Bean 注入业务代码。
 *
 * @since 2026-09-19
 */
@Slf4j
@Configuration
public class OAuth2AuthorizationServiceConfig {

    @Bean
    @Primary
    public SideIndexingOAuth2AuthorizationService sideIndexingOAuth2AuthorizationService(
            @Qualifier("inMemoryOAuth2AuthorizationService") OAuth2AuthorizationService delegate,
            StringRedisTemplate stringRedisTemplate,
            JwtUtils jwtUtils) {

        log.info("Wrapping default OAuth2AuthorizationService with SideIndexingOAuth2AuthorizationService");
        return new SideIndexingOAuth2AuthorizationService(delegate, stringRedisTemplate, jwtUtils);
    }
}
```

- [ ] **Step 3: Compile module**

```bash
mvn -pl auth -am compile -q
```

Expected: `BUILD SUCCESS`. If `inMemoryOAuth2AuthorizationService` qualifier fails to resolve, inspect actual bean name via test:

```java
@SpringBootTest
class BeanNameInspection {
    @Autowired ApplicationContext ctx;
    @Test void list() {
        Arrays.stream(ctx.getBeanNamesForType(OAuth2AuthorizationService.class)).forEach(System.out::println);
    }
}
```

If the bean name differs, adjust `@Qualifier(...)` to match.

- [ ] **Step 4: Run service tests — verify still pass (decorator is now a `@Service` AND a `@Bean`, may cause double registration)**

```bash
mvn -pl auth test -Dtest=OAuth2LogoutServiceImplTest,SideIndexingOAuth2AuthorizationServiceTest -q
```

If double-registration is a problem, drop the `@Service` annotation from `SideIndexingOAuth2AuthorizationService` and rely solely on the `@Bean` factory method. Document the choice with a comment.

- [ ] **Step 5: Commit**

```bash
git add auth/src/main/java/com/frog/auth/security/OAuth2AuthorizationServiceConfig.java
git commit -m "feat(auth): 装配 SideIndexingOAuth2AuthorizationService 为 @Primary Bean"
```

---

## Task 7: TDD refactor `OAuth2LogoutController` (split 2 endpoints)

**Files:**
- Create: `auth/src/test/java/com/frog/auth/controller/OAuth2LogoutControllerTest.java`
- Modify: `auth/src/main/java/com/frog/auth/controller/OAuth2LogoutController.java`

- [ ] **Step 1: Write failing controller tests**

Write `auth/src/test/java/com/frog/auth/controller/OAuth2LogoutControllerTest.java`:

```java
package com.frog.auth.controller;

import com.frog.auth.service.IOAuth2LogoutService;
import com.frog.common.security.util.HttpServletRequestUtils;
import com.frog.common.web.domain.SecurityUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = OAuth2LogoutController.class)
class OAuth2LogoutControllerTest {

    @Autowired MockMvc mockMvc;
    @MockBean IOAuth2LogoutService oauth2LogoutService;
    @MockBean HttpServletRequestUtils httpServletRequestUtils;

    @Test
    @WithMockUser(username = "alice", authorities = "ROLE_USER")
    void revokeByClient_callsServiceWithCallerUserId() throws Exception {
        UUID callerId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a1");
        SecurityUser principal = SecurityUser.builder()
                .userId(callerId).username("alice").authorities(Set.of()).build();

        mockMvc.perform(post("/oauth2/logout")
                        .param("clientId", "internal-service")
                        .with(user(principal)))
                .andExpect(status().isOk());

        verify(oauth2LogoutService, times(1))
                .revokeByClient(any(), eq("internal-service"), eq(callerId));
    }

    @Test
    @WithMockUser(username = "alice", authorities = {"ROLE_USER"})
    void revokeByClient_missingClientId_returns400() throws Exception {
        UUID callerId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a1");
        SecurityUser principal = SecurityUser.builder()
                .userId(callerId).username("alice").authorities(Set.of()).build();

        mockMvc.perform(post("/oauth2/logout")
                        .with(user(principal)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "admin", authorities = "oauth2:logout:global")
    void revokeGlobal_withAuthority_callsService() throws Exception {
        UUID callerId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a1");
        UUID targetId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a2");
        SecurityUser principal = SecurityUser.builder()
                .userId(callerId).username("admin").authorities(Set.of()).build();
        when(oauth2LogoutService.revokeGlobal(eq(targetId), eq("test"), eq("admin"))).thenReturn(3);

        mockMvc.perform(post("/oauth2/logout/all")
                        .param("userId", targetId.toString())
                        .param("reason", "test")
                        .with(user(principal)))
                .andExpect(status().isOk());

        verify(oauth2LogoutService).revokeGlobal(targetId, "test", "admin");
    }

    @Test
    @WithMockUser(username = "alice", authorities = "ROLE_USER")
    void revokeGlobal_withoutAuthority_returns403() throws Exception {
        UUID callerId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a1");
        UUID targetId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a2");
        SecurityUser principal = SecurityUser.builder()
                .userId(callerId).username("alice").authorities(Set.of()).build();

        mockMvc.perform(post("/oauth2/logout/all")
                        .param("userId", targetId.toString())
                        .param("reason", "test")
                        .with(user(principal)))
                .andExpect(status().isForbidden());
    }
}
```

- [ ] **Step 2: Run tests — verify failure**

```bash
mvn -pl auth test -Dtest=OAuth2LogoutControllerTest -q
```

Expected: tests FAIL (controller still has only one endpoint with wrong SpEL).

- [ ] **Step 3: Replace controller with thin two-endpoint version**

Replace `auth/src/main/java/com/frog/auth/controller/OAuth2LogoutController.java`:

```java
package com.frog.auth.controller;

import com.frog.auth.service.IOAuth2LogoutService;
import com.frog.common.log.annotation.AuditLog;
import com.frog.common.response.ApiResults;
import com.frog.common.security.util.HttpServletRequestUtils;
import com.frog.common.web.domain.SecurityUser;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * OAuth2 登出控制器
 *
 * <p>两个职责分离的端点:</p>
 * <ul>
 *   <li>{@code POST /oauth2/logout} - 单客户端撤销,需已登录</li>
 *   <li>{@code POST /oauth2/logout/all} - 全局撤销,需 {@code oauth2:logout:global} 权限</li>
 * </ul>
 *
 * @since 2025-11-10 (refactored 2026-09-19)
 */
@Slf4j
@Validated
@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
@Tag(name = "OAuth2 登出", description = "OAuth2 授权撤销管理")
public class OAuth2LogoutController {

    private final IOAuth2LogoutService oauth2LogoutService;
    private final HttpServletRequestUtils httpServletRequestUtils;

    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "OAuth2 单客户端撤销", description = "撤销当前用户在该客户端的 OAuth2 授权")
    public ApiResults<Void> revokeByClient(
            HttpServletRequest request,
            @RequestParam("clientId") @NotBlank(message = "clientId 不能为空") String clientId,
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
    @Operation(summary = "OAuth2 全局登出", description = "撤销指定用户的所有 OAuth2 授权(需 oauth2:logout:global 权限)")
    public ApiResults<Integer> revokeGlobal(
            @RequestParam("userId") UUID userId,
            @RequestParam("reason") @NotBlank(message = "reason 不能为空") String reason,
            @AuthenticationPrincipal SecurityUser caller) {

        int removed = oauth2LogoutService.revokeGlobal(userId, reason, caller.getUsername());
        return ApiResults.success(removed);
    }
}
```

- [ ] **Step 4: Run controller tests — verify pass**

```bash
mvn -pl auth test -Dtest=OAuth2LogoutControllerTest -q
```

Expected: `Tests run: 4, Failures: 0, Errors: 0, Skipped: 0`.

- [ ] **Step 5: Commit**

```bash
git add auth/src/test/java/com/frog/auth/controller/OAuth2LogoutControllerTest.java \
        auth/src/main/java/com/frog/auth/controller/OAuth2LogoutController.java
git commit -m "refactor(auth): OAuth2LogoutController 拆分为两条职责清晰端点 + 权限加固"
```

---

## Task 8: Module-level `mvn test` and final verification

**Files:** none (read-only verification)

- [ ] **Step 1: Compile and run all auth tests**

```bash
mvn -pl auth -am test -q
```

Expected: `BUILD SUCCESS`, all tests pass.

- [ ] **Step 2: Verify no stale references to old controller internals**

```bash
git diff HEAD~7 --stat
```

Expected: only files listed in §"File Structure" appear; no incidental edits.

- [ ] **Step 3: Smoke compile of dependent modules**

```bash
mvn -pl auth,gateway -am compile -q
```

Expected: `BUILD SUCCESS`.

- [ ] **Step 4: Verify git log**

```bash
git log --oneline -8
```

Expected: 8 commits (Tasks 1–8), each focused on one change.

- [ ] **Step 5: Manual acceptance — record evidence**

In a follow-up PR description, document:

1. `POST /oauth2/logout?clientId=X` with own token → 200
2. Same call with another user's token → 4001
3. `POST /oauth2/logout/all?userId=Y&reason=...` as admin → 200 + count
4. Same as non-admin → 403
5. Verify Redis key `oauth2:user:auths:{userId}` populated by `/oauth2/token` and decremented by `/oauth2/logout`

No automated code change; just doc notes.

---

## Self-Review Notes

- Spec coverage: G1–G7 from spec §1.2 mapped to Tasks 3–7.
- Type consistency: `OAuth2LogoutServiceImplTest` uses `OAuth2AuthorizationService` not `SideIndexingOAuth2AuthorizationService` — that's correct because we mock the interface contract; production injection is wired via `@Primary` in Task 6.
- `StringRedisTemplate` is provided automatically by Spring Boot's `RedisAutoConfiguration` — no extra bean needed.
- Test for `findByToken` / `findById` is included to lock in pass-through semantics (otherwise accidental proxy could shadow them).
- Migration SQL needs to be verified against actual table DDL — Step 3 of Task 1 enforces this.
- No silent dependencies on `JwtUtils` Redis methods; the decorator only reads from the JWT to extract userId at index time.

## Open Items Surfaced During Planning

- Whether `SideIndexingOAuth2AuthorizationService` should be `@Service` AND `@Bean` simultaneously — Task 6 Step 4 will reveal; if double-registration occurs, drop `@Service`.
- Bean name `inMemoryOAuth2AuthorizationService` is the conventional name but depends on Spring Security OAuth2 AS version — Task 6 Step 1 / Step 3 fallback path covers verification.