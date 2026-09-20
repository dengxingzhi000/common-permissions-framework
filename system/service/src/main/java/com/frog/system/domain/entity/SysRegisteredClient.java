package com.frog.system.domain.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableLogic;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.extension.handlers.JacksonTypeHandler;
import com.frog.common.mybatisPlus.handler.StringArrayTypeHandler;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

/**
 * OAuth2 注册客户端实体 — 对应 sys_registered_client 表(Phase 1.4)。
 *
 * <p>每个租户可以拥有多个 OAuth2 Client(网页、移动、服务端调用)。
 * 替代 {@code AuthorizationServerConfig} 中的硬编码 InMemory 客户端。
 *
 * <p>字段映射参考 Spring Authorization Server 的 {@code RegisteredClient}:
 * <ul>
 *   <li>clientAuthMethods / grantTypes / redirectUris / scopes — TEXT[]</li>
 *   <li>accessTokenTtlSeconds / refreshTokenTtlSeconds — INTEGER</li>
 *   <li>requireAuthorizationConsent / requireProofKey — BOOLEAN</li>
 * </ul>
 *
 * @author Deng
 * @since 2026-09-23
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@TableName(value = "sys_registered_client", autoResultMap = true)
@Tag(name = "SysRegisteredClient 对象", description = "OAuth2 注册客户端表")
public class SysRegisteredClient implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Schema(description = "主键ID")
    @TableId(value = "id", type = IdType.NONE)
    private UUID id;

    @Schema(description = "租户ID(逻辑外键 → sys_tenant.id)")
    @TableField("tenant_id")
    private UUID tenantId;

    @Schema(description = "应用ID(逻辑外键 → sys_application.id,可空)")
    @TableField("application_id")
    private UUID applicationId;

    @Schema(description = "OAuth2 client_id(全局唯一)")
    @TableField("client_id")
    private String clientId;

    @Schema(description = "client_secret BCrypt 哈希(公开客户端为 NULL)")
    @TableField("client_secret_hash")
    private String clientSecretHash;

    @Schema(description = "客户端认证方式:client_secret_basic / client_secret_post / none")
    @TableField(value = "client_auth_methods", typeHandler = StringArrayTypeHandler.class)
    private String[] clientAuthMethods;

    @Schema(description = "授权类型:authorization_code / refresh_token / client_credentials")
    @TableField(value = "grant_types", typeHandler = StringArrayTypeHandler.class)
    private String[] grantTypes;

    @Schema(description = "OAuth2 redirect_uris")
    @TableField(value = "redirect_uris", typeHandler = StringArrayTypeHandler.class)
    private String[] redirectUris;

    @Schema(description = "登出后跳转 URI")
    @TableField(value = "post_logout_redirect_uris", typeHandler = StringArrayTypeHandler.class)
    private String[] postLogoutRedirectUris;

    @Schema(description = "OAuth2 scopes")
    @TableField(value = "scopes", typeHandler = StringArrayTypeHandler.class)
    private String[] scopes;

    @Schema(description = "是否需要授权确认页")
    @TableField("require_authorization_consent")
    private Boolean requireAuthorizationConsent;

    @Schema(description = "是否强制 PKCE")
    @TableField("require_proof_key")
    private Boolean requireProofKey;

    @Schema(description = "Access Token 有效期(秒)")
    @TableField("access_token_ttl_seconds")
    private Integer accessTokenTtlSeconds;

    @Schema(description = "Refresh Token 有效期(秒)")
    @TableField("refresh_token_ttl_seconds")
    private Integer refreshTokenTtlSeconds;

    @Schema(description = "状态:0-禁用,1-启用")
    @TableField("status")
    private Integer status;

    @Schema(description = "审计扩展字段(JSONB)")
    @TableField(value = "audit", typeHandler = JacksonTypeHandler.class)
    private Map<String, Object> audit;

    @Schema(description = "创建时间")
    @TableField(value = "create_time", fill = FieldFill.INSERT)
    private LocalDateTime createTime;

    @Schema(description = "更新时间")
    @TableField(value = "update_time", fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updateTime;

    @Schema(description = "逻辑删除")
    @TableLogic(value = "false", delval = "true")
    @TableField("deleted")
    private Boolean deleted;

    /**
     * 是否处于启用状态。
     */
    public boolean isActive() {
        return status != null && status == 1;
    }
}
