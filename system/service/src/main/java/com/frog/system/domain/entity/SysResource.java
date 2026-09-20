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
 * 资源目录实体 — 对应 sys_resource 表(Phase 1.7)。
 *
 * <p>将原本 stringly-typed 的 {@code sys_data_permission_rule.resource_type}
 * 升级为可被外键引用的类型化目录。每个资源隶属于 {@link SysTenant} 与
 * {@link SysApplication},以 {@code resource_code} 作为租户+应用内唯一标识。
 *
 * @author Deng
 * @since 2026-09-24
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@TableName(value = "sys_resource", autoResultMap = true)
@Tag(name = "SysResource 对象", description = "资源目录表")
public class SysResource implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Schema(description = "资源ID")
    @TableId(value = "id", type = IdType.NONE)
    private UUID id;

    @Schema(description = "租户ID(NULL 表示跨租户共享资源)")
    @TableField("tenant_id")
    private UUID tenantId;

    @Schema(description = "应用ID")
    @TableField("app_id")
    private UUID appId;

    @Schema(description = "资源编码(租户+应用内唯一)")
    @TableField("resource_code")
    private String resourceCode;

    @Schema(description = "资源名称")
    @TableField("resource_name")
    private String resourceName;

    @Schema(description = "资源类型(如 PROJECT / DOCUMENT / INVOICE)")
    @TableField("resource_type")
    private String resourceType;

    @Schema(description = "父资源ID,NULL 表示根资源")
    @TableField("parent_id")
    private UUID parentId;

    @Schema(description = "资源描述")
    @TableField("description")
    private String description;

    @Schema(description = "扩展元数据(JSONB)")
    @TableField(value = "metadata", typeHandler = JacksonTypeHandler.class)
    private Map<String, Object> metadata;

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
     * 是否处于启用状态
     */
    public boolean isActive() {
        return status != null && status == 1;
    }
}