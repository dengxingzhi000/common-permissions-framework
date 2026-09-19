package com.frog.common.log.service.Impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.frog.common.data.audit.SysAuditLogMapper;
import com.frog.common.data.audit.SysAuditLogPO;
import com.frog.common.security.audit.SysAuditLog;
import com.frog.common.log.service.ISysAuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * <p>
 * 操作审计日志表 服务实现类
 * </p>
 *
 * @author author
 * @since 2025-10-14
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SysAuditLogServiceImpl extends ServiceImpl<SysAuditLogMapper, SysAuditLogPO>
        implements ISysAuditLogService {

    private final SysAuditLogMapper sysAuditLogMapper;

    private void insertFromPojo(SysAuditLog source) {
        SysAuditLogPO po = new SysAuditLogPO();
        BeanUtils.copyProperties(source, po);
        sysAuditLogMapper.insert(po);
    }

    @Async
    public void recordLogin(UUID userId, String username, String ipAddress,
                            boolean success, String remark) {
        SysAuditLog log = SysAuditLog.builder()
                .userId(userId)
                .username(username)
                .operationType("LOGIN")
                .ipAddress(ipAddress)
                .status(success ? 1 : 0)
                .operationDesc(remark)
                .createTime(LocalDateTime.now())
                .build();
        insertFromPojo(log);
    }

    @Async
    public void recordLoginFailure(String username, String ipAddress, String reason) {
        SysAuditLog log = SysAuditLog.builder()
                .username(username)
                .operationType("LOGIN_FAILURE")
                .ipAddress(ipAddress)
                .status(0)
                .errorMsg(reason)
                .createTime(LocalDateTime.now())
                .build();
        insertFromPojo(log);
    }

    @Async
    public void recordLogout(UUID userId, String remark) {
        SysAuditLog log = SysAuditLog.builder()
                .userId(userId)
                .operationType("LOGOUT")
                .status(1)
                .operationDesc(remark)
                .createTime(LocalDateTime.now())
                .build();
        insertFromPojo(log);
    }

    /**
     * 记录安全事件（异步）
     */
    @Async
    public void recordSecurityEvent(String eventType, Integer riskLevel, UUID userId,
                                    String username, String ipAddress,
                                    String resource, boolean success, String details) {
        try {
            SysAuditLog log = SysAuditLog.builder()
                    .userId(userId)
                    .username(username)
                    .operationType(eventType)
                    .riskLevel(riskLevel)
                    .ipAddress(ipAddress)
                    .operationModule(resource)
                    .operationDesc(details)
                    .status(success ? 1 : 0)
                    .createTime(LocalDateTime.now())
                    .build();

            insertFromPojo(log);

            // 高风险事件立即告警
            if (riskLevel != null && riskLevel >= 4) {
                sendAlert(log);
            }
        } catch (Exception e) {
            log.error("Failed to record security event", e);
        }
    }

    /**
     * 发送告警
     */
    private void sendAlert(SysAuditLog auditLog) {
        // TODO: 集成告警系统（企业微信、钉钉、邮件）
        log.warn("Security Alert: {}, User: {}, IP: {}",
                auditLog.getOperationType(), auditLog.getUsername(), auditLog.getIpAddress());
    }
}
