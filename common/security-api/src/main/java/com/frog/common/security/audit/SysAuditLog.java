package com.frog.common.security.audit;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * 操作审计日志 (纯 POJO，不含 MyBatis-Plus 注解).
 * <p>
 * 用于跨模块传输 / DTO 暴露；持久化使用 {@code com.frog.common.data.audit.SysAuditLogPO}。
 * 数据库主表 {@code sys_audit_log} 由 (id, create_time) 复合主键定义，且按月分区。
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SysAuditLog {

    private UUID id;
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
    private LocalDateTime createTime;
}
