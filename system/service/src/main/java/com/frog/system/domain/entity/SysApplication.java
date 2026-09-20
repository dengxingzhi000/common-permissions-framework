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
 * 应用实体 — 对应 sys_application 表(Phase 1.1)。
 *
 * <p>隶属于 {@link SysTenant}。每个应用是租户内部的一组权限/资源的逻辑分组,
 * 例如一个 SaaS 产品、一个管理后台、一个移动 App。
 *
 * @author Deng
 * @since 2026-09-22
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@TableName(value = "sys_application", autoResultMap = true)
@Tag(name = "SysApplication 对象", description = "应用表")
public class SysApplication implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Schema(description = "应用ID")
    @TableId(value = "id", type = IdType.NONE)
    private UUID id;

    @Schema(description = "租户ID")
    @TableField("tenant_id")
    private UUID tenantId;

    @Schema(description = "应用编码(租户内唯一)")
    @TableField("app_code")
    private String appCode;

    @Schema(description = "应用名称")
    @TableField("app_name")
    private String appName;

    @Schema(description = "应用密钥哈希(BCrypt或SHA256)")
    @TableField("app_secret_hash")
    private String appSecretHash;

    @Schema(description = "应用类型:1-Web,2-Mobile,3-Service")
    @TableField("app_type")
    private Integer appType;

    @Schema(description = "OAuth2 redirect_uris")
    @TableField(value = "redirect_uris", typeHandler = StringArrayTypeHandler.class)
    private String[] redirectUris;

    @Schema(description = "OAuth2 scopes")
    @TableField(value = "scopes", typeHandler = StringArrayTypeHandler.class)
    private String[] scopes;

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
     * 应用类型常量
     */
    public static final class Type {
        public static final int WEB = 1;
        public static final int MOBILE = 2;
        public static final int SERVICE = 3;

        private Type() {
        }
    }

    /**
     * 是否处于启用状态
     */
    public boolean isActive() {
        return status != null && status == 1;
    }
}
