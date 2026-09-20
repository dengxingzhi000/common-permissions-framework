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
 * 授权实体 — 对应 sys_grant 表(Phase 1.8a)。
 *
 * <p>统一的授权元组,取代之前分散在 sys_user_role 与 sys_user_permission 中的
 * "用户→角色/权限" 关联。每条 Grant 链接一个 Subject(user | service_account)
 * 到一个 Target(role | permission | resource),并显式声明 effect、priority、
 * scope 与时间窗口。
 *
 * <p>评估算法由 {@link com.frog.system.decision.DecisionServiceImpl} 实现:
 * deny 在同优先级压倒 allow;数值更高的 priority 压倒数值低的 priority。
 *
 * @author Deng
 * @since 2026-09-24
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@TableName(value = "sys_grant", autoResultMap = true)
@Tag(name = "SysGrant 对象", description = "授权实体表")
public class SysGrant implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Schema(description = "授权ID")
    @TableId(value = "id", type = IdType.NONE)
    private UUID id;

    @Schema(description = "租户ID")
    @TableField("tenant_id")
    private UUID tenantId;

    @Schema(description = "应用ID")
    @TableField("app_id")
    private UUID appId;

    @Schema(description = "主体类型: user | service_account")
    @TableField("subject_type")
    private String subjectType;

    @Schema(description = "主体ID")
    @TableField("subject_id")
    private UUID subjectId;

    @Schema(description = "目标类型: role | permission | resource")
    @TableField("target_type")
    private String targetType;

    @Schema(description = "目标ID(角色/权限/资源)")
    @TableField("target_id")
    private UUID targetId;

    @Schema(description = "动作(如 project.read),对 permission/resource 类型生效")
    @TableField("action")
    private String action;

    @Schema(description = "可选资源类型约束")
    @TableField("resource_type_filter")
    private String resourceTypeFilter;

    @Schema(description = "效果: allow | deny")
    @TableField("effect")
    private String effect;

    @Schema(description = "优先级,数值越大越优先;deny 在同优先级压倒 allow")
    @TableField("priority")
    private Integer priority;

    @Schema(description = "可选部门/组织范围")
    @TableField("scope_org_id")
    private UUID scopeOrgId;

    @Schema(description = "可选特定资源实例范围")
    @TableField("scope_resource_id")
    private String scopeResourceId;

    @Schema(description = "生效时间,NULL 表示即时生效")
    @TableField("effective_time")
    private LocalDateTime effectiveTime;

    @Schema(description = "过期时间,NULL 表示永不过期")
    @TableField("expire_time")
    private LocalDateTime expireTime;

    @Schema(description = "授权人")
    @TableField("granted_by")
    private UUID grantedBy;

    @Schema(description = "授权原因(审计/SoD 上下文)")
    @TableField("grant_reason")
    private String grantReason;

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

    /** 主体类型常量 */
    public static final class Subject {
        public static final String USER = "user";
        public static final String SERVICE_ACCOUNT = "service_account";
        private Subject() {}
    }

    /** 目标类型常量 */
    public static final class Target {
        public static final String ROLE = "role";
        public static final String PERMISSION = "permission";
        public static final String RESOURCE = "resource";
        private Target() {}
    }

    /** 效果常量 */
    public static final class Effect {
        public static final String ALLOW = "allow";
        public static final String DENY = "deny";
        private Effect() {}
    }
}