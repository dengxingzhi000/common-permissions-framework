package com.frog.common.log.aspect;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.frog.common.data.audit.SysAuditLogMapper;
import com.frog.common.data.audit.SysAuditLogPO;
import com.frog.common.log.annotation.AuditLog;
import com.frog.common.security.audit.SysAuditLog;
import com.frog.common.security.util.DesensitizeUtils;
import com.frog.common.security.util.IpUtils;
import com.frog.common.web.util.SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;

/**
 * 审计日志 AOP切面
 *
 * @author Deng
 * createData 2025/10/14 17:23
 * @version 1.0
 */
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class SysAuditLogAspect {

    private final SysAuditLogMapper sysAuditLogMapper;

    @Setter
    private ObjectMapper objectMapper;

    @Around("@annotation(com.frog.common.log.annotation.AuditLog)")
    public Object around(ProceedingJoinPoint point) throws Throwable {
        long startTime = System.currentTimeMillis();

        // 获取注解
        MethodSignature signature = (MethodSignature) point.getSignature();
        AuditLog annotation = signature.getMethod().getAnnotation(AuditLog.class);

        // 获取请求信息
        ServletRequestAttributes attributes =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attributes != null ? attributes.getRequest() : null;

        SysAuditLog auditLog = SysAuditLog.builder()
                .userId(SecurityUtils.getCurrentUserUuid().orElse(null))
                .username(SecurityUtils.getCurrentUsername().orElse(null))
                .operationType(annotation.businessType())
                .operationDesc(annotation.operation())
                .riskLevel(annotation.riskLevel())
                .build();

        if (request != null) {
            auditLog.setRequestUri(request.getRequestURI());
            auditLog.setRequestMethod(request.getMethod());
            auditLog.setIpAddress(IpUtils.getClientIp(request));
            auditLog.setUserAgent(request.getHeader("User-Agent"));

            // 记录请求参数
            if (annotation.recordParams()) {
                try {
                    Object[] args = point.getArgs();
                    String params = objectMapper.writeValueAsString(args);
                    // 敏感信息脱敏
                    params = DesensitizeUtils.desensitize(params);
                    auditLog.setRequestParams(params);
                } catch (Exception e) {
                    log.error("Failed to serialize request params", e);
                }
            }
        }

        Object result;
        try {
            // 执行方法
            result = point.proceed();
            auditLog.setStatus(1);

            // 记录响应结果
            if (annotation.recordResult() && result != null) {
                try {
                    String response = objectMapper.writeValueAsString(result);
                    auditLog.setResponseData(DesensitizeUtils.desensitize(response));
                } catch (Exception e) {
                    log.error("Failed to serialize response", e);
                }
            }

        } catch (Exception e) {
            auditLog.setStatus(0);
            auditLog.setErrorMsg(e.getMessage());
            throw e;
        } finally {
            long executeTime = System.currentTimeMillis() - startTime;
            auditLog.setExecuteTime((int) executeTime);
            auditLog.setCreateTime(LocalDateTime.now());

            // 异步保存日志
            try {
                SysAuditLogPO po = new SysAuditLogPO();
                BeanUtils.copyProperties(auditLog, po);
                sysAuditLogMapper.insert(po);
            } catch (Exception e) {
                log.error("Failed to save audit log", e);
            }
        }

        return result;
    }
}
