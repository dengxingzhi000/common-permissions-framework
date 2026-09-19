package com.frog.common.data.audit;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * 操作审计日志持久化对象 (MyBatis-Plus 注解).
 * <p>
 * 数据库表 {@code sys_audit_log} 复合主键为 {@code (id, create_time)}，按月分区。
 * id 类型必须为 {@link IdType#ASSIGN_UUID}，与表 {@code id UUID DEFAULT gen_random_uuid()} 一致。
 */
@Data
@TableName(value = "sys_audit_log", autoResultMap = true)
public class SysAuditLogPO {

    @TableId(value = "id", type = IdType.ASSIGN_UUID)
    private UUID id;

    @TableField(value = "create_time", fill = FieldFill.INSERT)
    private LocalDateTime createTime;

    private UUID userId;
    private String username;
    private String realName;
    private UUID deptId;
    private String operationType;
    private String operationModule;
    private String operationDesc;
    private String requestUri;
    private String requestMethod;
    private String requestParams;
    private String responseData;
    private Integer responseStatus;
    private String ipAddress;
    private String location;
    private String userAgent;
    private String businessType;
    private String businessId;
    private String oldValue;
    private String newValue;
    private Integer riskLevel;
    private Integer status;
    private String errorMsg;
    private Integer executeTime;
}
