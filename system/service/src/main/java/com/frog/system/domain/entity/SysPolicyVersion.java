package com.frog.system.domain.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
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
 * 策略版本实体 — 对应 sys_policy_version 表(Phase 1.8b)。
 *
 * <p>记录每次发布的授权策略快照。{@code policy_snapshot} 冻结发布时的
 * 角色权限映射与授权集合,以便后续决策评估可以追溯到具体的策略版本。
 *
 * @author Deng
 * @since 2026-09-24
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@TableName(value = "sys_policy_version", autoResultMap = true)
@Tag(name = "SysPolicyVersion 对象", description = "策略版本表")
public class SysPolicyVersion implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Schema(description = "策略版本ID")
    @TableId(value = "id", type = IdType.NONE)
    private UUID id;

    @Schema(description = "版本标签(全局唯一,如 v20260924-001)")
    @TableField("version")
    private String version;

    @Schema(description = "租户ID,NULL 表示跨租户共享策略")
    @TableField("tenant_id")
    private UUID tenantId;

    @Schema(description = "应用ID,NULL 表示跨应用共享策略")
    @TableField("app_id")
    private UUID appId;

    @Schema(description = "版本说明")
    @TableField("description")
    private String description;

    @Schema(description = "策略快照(JSONB): 角色权限+授权集")
    @TableField(value = "policy_snapshot", typeHandler = JacksonTypeHandler.class)
    private Map<String, Object> policySnapshot;

    @Schema(description = "激活时间")
    @TableField("activated_at")
    private LocalDateTime activatedAt;

    @Schema(description = "激活人")
    @TableField("activated_by")
    private UUID activatedBy;

    @Schema(description = "状态: draft | active | archived")
    @TableField("status")
    private String status;

    @Schema(description = "创建时间")
    @TableField(value = "create_time", fill = FieldFill.INSERT)
    private LocalDateTime createTime;

    /** 状态常量 */
    public static final class Status {
        public static final String DRAFT = "draft";
        public static final String ACTIVE = "active";
        public static final String ARCHIVED = "archived";
        private Status() {}
    }
}