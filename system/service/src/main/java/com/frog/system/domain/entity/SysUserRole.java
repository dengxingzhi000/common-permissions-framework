package com.frog.system.domain.entity;

import com.baomidou.mybatisplus.annotation.*;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.experimental.Accessors;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * 用户角色关联表 - 支持临时角色授权
 *
 * @author Deng
 * @since 2025-12-15
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@TableName("sys_user_role")
@Tag(
        name = "SysUserRole 对象",
        description = "用户角色关联表"
)
public class SysUserRole implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    @Schema(description = "主键 ID")
    @TableId(value = "id", type = IdType.ASSIGN_UUID)
    private UUID id;

    @Schema(description = "用户 ID")
    private UUID userId;

    @Schema(description = "角色 ID")
    private UUID roleId;

    @Schema(description = "租户 ID(Phase 1.2; NULL 兼容 legacy)")
    @TableField("tenant_id")
    private UUID tenantId;

    @Schema(description = "生效时间(临时授权)")
    private LocalDateTime effectiveTime;

    @Schema(description = "过期时间(临时授权)")
    private LocalDateTime expireTime;

    @Schema(description = "审批状态:0-待审批,1-审批中,2-已批准,3-已拒绝")
    private Integer approvalStatus;

    @Schema(description = "审批人")
    private UUID approvedBy;

    @Schema(description = "审批时间")
    private LocalDateTime approvedTime;

    @Schema(description = "创建时间")
    @TableField(value = "create_time", fill = FieldFill.INSERT)
    private LocalDateTime createTime;

    @Schema(description = "创建人")
    @TableField(value = "create_by", fill = FieldFill.INSERT)
    private UUID createBy;

    // ==================== 冗余字段（来自 db_user.sys_user）====================

    @Schema(description = "用户名（冗余字段）")
    @TableField("username")
    private String username;

    @Schema(description = "真实姓名（冗余字段）")
    @TableField("real_name")
    private String realName;

    @Schema(description = "用户状态（冗余字段）")
    @TableField("user_status")
    private Integer userStatus;

    /**
     * 审批状态枚举
     */
    @Getter
    public enum ApprovalStatus {
        PENDING(0, "待审批"),
        IN_PROGRESS(1, "审批中"),
        APPROVED(2, "已批准"),
        REJECTED(3, "已拒绝");

        private final int code;
        private final String desc;

        ApprovalStatus(int code, String desc) {
            this.code = code;
            this.desc = desc;
        }
    }

    /**
     * 判断是否为临时授权
     */
    public boolean isTemporary() {
        return effectiveTime != null && expireTime != null;
    }

    /**
     * 判断是否在有效期内
     */
    public boolean isEffective() {
        if (approvalStatus == null || approvalStatus != ApprovalStatus.APPROVED.getCode()) {
            return false;
        }
        if (!isTemporary()) {
            return true; // 永久授权
        }
        LocalDateTime now = LocalDateTime.now();
        return now.isAfter(effectiveTime) && now.isBefore(expireTime);
    }
}
