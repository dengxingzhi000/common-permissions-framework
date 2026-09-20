package com.frog.common.security.oauth2;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * OAuth2 注册客户端 DTO — Phase 1.4。
 *
 * <p>跨模块传输用的纯 POJO,不带 MyBatis-Plus 注解;
 * 持久化实体见
 * {@code com.frog.system.domain.entity.SysRegisteredClient}。
 *
 * <p>字段含义与 Spring Authorization Server 的 {@code RegisteredClient}
 * 对齐 — 见 {@code sys_registered_client} 表 DDL。
 *
 * <p>故意省略的字段:
 * <ul>
 *   <li>{@code Map<String,Object> audit} — JSONB 审计扩展,不进入 API 表面</li>
 *   <li>{@code Boolean deleted} — 软删除标记,内部状态不暴露</li>
 *   <li>{@code isActive()} — 调用方按需内联 {@code status == 1} 判断</li>
 * </ul>
 *
 * @author Deng
 * @since 2026-09-23
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SysRegisteredClientDTO {

    private UUID id;

    private UUID tenantId;

    private UUID applicationId;

    private String clientId;

    private String clientSecretHash;

    private String[] clientAuthMethods;

    private String[] grantTypes;

    private String[] redirectUris;

    private String[] postLogoutRedirectUris;

    private String[] scopes;

    private Boolean requireAuthorizationConsent;

    private Boolean requireProofKey;

    private Integer accessTokenTtlSeconds;

    private Integer refreshTokenTtlSeconds;

    private Integer status;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}
