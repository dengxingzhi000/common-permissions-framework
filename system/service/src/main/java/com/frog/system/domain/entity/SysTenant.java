package com.frog.system.domain.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableLogic;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.extension.handlers.JacksonTypeHandler;
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
 * 租户实体 — 对应 sys_tenant 表(Phase 1.1)。
 *
 * <p>多租户基础表。每个租户可拥有多个 Application(子表)。
 *
 * @author Deng
 * @since 2026-09-22
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@TableName(value = "sys_tenant", autoResultMap = true)
@Tag(name = "SysTenant 对象", description = "租户表")
public class SysTenant implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Schema(description = "租户ID")
    @TableId(value = "id", type = IdType.NONE)
    private UUID id;

    @Schema(description = "租户编码(全局唯一)")
    @TableField("tenant_code")
    private String tenantCode;

    @Schema(description = "租户名称")
    @TableField("tenant_name")
    private String tenantName;

    @Schema(description = "状态:0-禁用,1-启用")
    @TableField("status")
    private Integer status;

    @Schema(description = "隔离级别:1-共享,2-独立Schema,3-独立DB")
    @TableField("isolation_level")
    private Integer isolationLevel;

    @Schema(description = "用户上限")
    @TableField("max_users")
    private Integer maxUsers;

    @Schema(description = "到期时间")
    @TableField("expires_at")
    private LocalDateTime expiresAt;

    @Schema(description = "联系邮箱")
    @TableField("contact_email")
    private String contactEmail;

    @Schema(description = "审计扩展字段(JSONB)")
    @TableField(value = "audit", typeHandler = JacksonTypeHandler.class)
    private Map<String, Object> audit;

    @Schema(description = "创建时间")
    @TableField(value = "create_time", fill = FieldFill.INSERT)
    private LocalDateTime createTime;

    @Schema(description = "更新时间")
    @TableField(value = "update_time", fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updateTime;

    @Schema(description = "创建人")
    @TableField(value = "create_by", fill = FieldFill.INSERT)
    private UUID createBy;

    @Schema(description = "更新人")
    @TableField(value = "update_by", fill = FieldFill.INSERT_UPDATE)
    private UUID updateBy;

    @Schema(description = "逻辑删除")
    @TableLogic(value = "false", delval = "true")
    @TableField("deleted")
    private Boolean deleted;

    /**
     * 隔离级别常量
     */
    public static final class Isolation {
        public static final int SHARED = 1;
        public static final int SCHEMA = 2;
        public static final int DATABASE = 3;

        private Isolation() {
        }
    }

    /**
     * 是否处于启用状态
     */
    public boolean isActive() {
        return status != null && status == 1;
    }

    /**
     * 是否已过期
     */
    public boolean isExpired() {
        return expiresAt != null && expiresAt.isBefore(LocalDateTime.now());
    }
}
