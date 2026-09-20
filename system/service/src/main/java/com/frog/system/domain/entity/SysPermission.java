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
 * 权限表
 * </p>
 *
 * @author author
 * @since 2025-10-14
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@TableName("sys_permission")
@Tag(
        name="SysPermission 对象",
        description="权限表"
)
public class SysPermission implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    @Schema(description = "权限 ID")
    @TableId(value = "id", type = IdType.NONE)
    private UUID id;

    @Schema(description = "父级 ID")
    private UUID parentId;

    @Schema(description = "权限编码")
    private String permissionCode;

    @Schema(description = "权限名称")
    private String permissionName;

    @Schema(description = "类型:1-目录,2-菜单,3-按钮,4-API,5-数据")
    private Integer permissionType;

    @Schema(description = "路由地址")
    private String routePath;

    @Schema(description = "组件路径")
    private String component;

    @Schema(description = "重定向地址")
    private String redirect;

    @Schema(description = "图标")
    private String icon;

    @Schema(description = "API路径(支持通配符)")
    private String apiPath;

    @Schema(description = "HTTP方法(GET,POST,PUT,DELETE,*)")
    private String httpMethod;

    @Schema(description = "权限等级:1-普通,2-敏感,3-机密,4-绝密")
    private Integer permissionLevel;

    @Schema(description = "风险等级:1-低,2-中,3-高,4-极高")
    private Integer riskLevel;

    @Schema(description = "是否需要审批")
    private Boolean needApproval;

    @Schema(description = "是否需要双因素认证")
    private Boolean needTwoFactor;

    @Schema(description = "排序")
    private Integer sortOrder;

    @Schema(description = "是否可见")
    private Boolean visible;

    @Schema(description = "状态")
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
    private Boolean deleted;
}
