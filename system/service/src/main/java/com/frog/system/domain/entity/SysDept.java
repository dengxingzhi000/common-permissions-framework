package com.frog.system.domain.entity;

import com.baomidou.mybatisplus.annotation.*;

import java.io.Serial;
import java.time.LocalDateTime;
import java.io.Serializable;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

/**
 * <p>
 * 部门表
 * </p>
 *
 * @author author
 * @since 2025-11-07
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@TableName("sys_dept")
@Tag(name="SysDept 对象", description="部门表")
public class SysDept implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    @Schema(name = "部门 ID")
    @TableId(value = "id", type = IdType.NONE)
    private UUID id;

    @Schema(description = "父部门 ID")
    @TableField("parent_id")
    private UUID parentId;

    @Schema(description = "部门编码")
    @TableField("dept_code")
    private String deptCode;

    @Schema(description = "部门名称")
    @TableField("dept_name")
    private String deptName;

    @Schema(description = "部门类型:1-业务部门,2-管理部门,3-支持部门")
    @TableField("dept_type")
    private Integer deptType;

    @Schema(description = "部门负责人 ID")
    @TableField("leader_id")
    private UUID leaderId;

    @Schema(description = "联系电话")
    @TableField("phone")
    private String phone;

    @Schema(description = "邮箱")
    @TableField("email")
    private String email;

    @Schema(description = "数据隔离级别:1-普通,2-加密,3-完全隔离")
    @TableField("isolation_level")
    private Integer isolationLevel;

    @Schema(description = "排序")
    @TableField("sort_order")
    private Integer sortOrder;

    @Schema(description = "状态")
    @TableField("status")
    private Integer status;

    @Schema(description = "租户 ID(Phase 1.2; NULL 兼容 legacy)")
    @TableField("tenant_id")
    private UUID tenantId;

    @Schema(description = "创建时间")
    @TableField(value = "create_time", fill = FieldFill.INSERT)
    private LocalDateTime createTime;

    @Schema(description = "创建人")
    @TableField(value = "create_by", fill = FieldFill.INSERT)
    private UUID createBy;

    @Schema(description = "更新时间")
    @TableField(value = "update_time", fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updateTime;

    @Schema(description = "更新人")
    @TableField(value = "update_by", fill = FieldFill.INSERT_UPDATE)
    private UUID updateBy;

    @Schema(description = "逻辑删除")
    @TableLogic(value = "false", delval = "true")
    @TableField("deleted")
    private Boolean deleted;

    // ==================== 冗余字段（来自 db_user.sys_user）====================

    @Schema(description = "负责人姓名（冗余字段）")
    @TableField("leader_name")
    private String leaderName;

    @Schema(description = "负责人电话（冗余字段）")
    @TableField("leader_phone")
    private String leaderPhone;
}
