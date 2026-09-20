package com.frog.system.domain.entity;

import com.baomidou.mybatisplus.annotation.*;

import java.io.Serial;
import java.time.LocalDateTime;
import java.io.Serializable;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

/**
 * <p>
 * 用户表(UUID主键)
 * </p>
 *
 * @author author
 * @since 2025-10-14
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@TableName("sys_user")
@Schema(
        name="SysUser 对象",
        description="用户表(UUID主键)"
)
public class SysUser implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    @Schema(description = "用户ID(UUID存储)")
    @TableId(
            value = "id",
            type = IdType.NONE
    )
    private UUID id;

    @Schema(description = "用户名")
    @TableField("username")
    private String username;

    @Schema(description = "密码(BCrypt加密)")
    @TableField("password")
    private String password;

    @Schema(description = "真实姓名")
    @TableField("real_name")
    private String realName;

    @Schema(description = "身份证号(加密存储)")
    @TableField("id_card")
    private String idCard;

    @Schema(description = "邮箱")
    @TableField("email")
    private String email;

    @Schema(description = "手机号")
    @TableField("phone")
    private String phone;

    @Schema(description = "头像 URL")
    @TableField("avatar")
    private String avatar;

    @Schema(description = "状态:0-禁用,1-启用,2-锁定")
    @TableField("status")
    private Integer status;

    @Schema(description = "部门 ID")
    @TableField("dept_id")
    private UUID deptId;

    @Schema(description = "租户 ID(Phase 1.2; NULL 兼容 legacy 单租户数据)")
    @TableField("tenant_id")
    private UUID tenantId;

    @Schema(description = "用户级别:1-普通,2-高级,3-VIP")
    @TableField("user_level")
    private Integer userLevel;

    @Schema(description = "账户类型:1-内部员工,2-外部审计,3-系统管理员")
    @TableField("account_type")
    private Integer accountType;

    @Schema(description = "连续登录失败次数")
    @TableField("login_attempts")
    private Integer loginAttempts;

    @Schema(description = "锁定截止时间")
    @TableField("locked_until")
    private LocalDateTime lockedUntil;

    @Schema(description = "密码过期时间")
    @TableField("password_expire_time")
    private LocalDateTime passwordExpireTime;

    @Schema(description = "是否强制修改密码")
    @TableField("force_change_password")
    private Boolean forceChangePassword;

    @Schema(description = "是否启用双因素认证")
    @TableField("two_factor_enabled")
    private Boolean twoFactorEnabled;

    @Schema(description = "双因素认证密钥")
    @TableField("two_factor_secret")
    private String twoFactorSecret;

    @Schema(description = "创建时间")
    @TableField(value = "create_time", fill = FieldFill.INSERT)
    private LocalDateTime createTime;

    @Schema(description = "创建人 ID")
    @TableField(value = "create_by", fill = FieldFill.INSERT)
    private UUID createBy;

    @Schema(description = "更新时间")
    @TableField(value = "update_time", fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updateTime;

    @Schema(description = "更新人 ID")
    @TableField(value = "update_by", fill = FieldFill.INSERT_UPDATE)
    private UUID updateBy;

    @Schema(description = "最后登录时间")
    @TableField("last_login_time")
    private LocalDateTime lastLoginTime;

    @Schema(description = "最后登录 IP")
    @TableField("last_login_ip")
    private String lastLoginIp;

    @Schema(description = "最后修改密码时间")
    @TableField("last_password_change_time")
    private LocalDateTime lastPasswordChangeTime;

    @Schema(description = "逻辑删除")
    @TableLogic(value = "false", delval = "true")
    @TableField("deleted")
    private Boolean deleted;

    @Schema(description = "备注")
    @TableField("remark")
    private String remark;
}
