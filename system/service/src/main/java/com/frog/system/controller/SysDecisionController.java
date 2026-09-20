package com.frog.system.controller;

import com.frog.common.response.ApiResults;
import com.frog.system.decision.CheckRequest;
import com.frog.system.decision.Decision;
import com.frog.system.decision.DecisionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * 授权决策控制器 — 数据平面入口(Phase 1.8d/e)。
 *
 * <p>这是平台对外暴露的"我能做这件事吗?"问题的统一入口。
 * 任何已认证用户(包括服务账号 JWT)均可调用 POST 端点;
 * 权限集合查询为控制面操作,要求 {@code system:admin}。
 *
 * @author Deng
 * @since 2026-09-24
 */
@RestController
@RequestMapping("/v1/decision")
@RequiredArgsConstructor
@Tag(name = "授权决策", description = "数据平面决策 API(Phase 1.8d/e)")
public class SysDecisionController {

    private final DecisionService decisionService;

    /**
     * 单次授权决策
     */
    @PostMapping("/check")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "单次授权决策",
            description = "输入 CheckRequest,返回 allow/deny + reason + policyVersion + decisionId")
    public ApiResults<Decision> check(
            @Parameter(description = "决策请求") @RequestBody CheckRequest request) {
        return ApiResults.success(decisionService.check(request));
    }

    /**
     * 批量授权决策
     */
    @PostMapping("/batch-check")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "批量授权决策", description = "减少网络开销,顺序与请求对应")
    public ApiResults<List<Decision>> batchCheck(
            @Parameter(description = "决策请求列表") @RequestBody List<CheckRequest> requests) {
        return ApiResults.success(decisionService.batchCheck(requests));
    }

    /**
     * 查询主体有效权限集合(SDK 水合用)
     */
    @GetMapping("/permissions")
    @PreAuthorize("hasAuthority('system:admin')")
    @Operation(summary = "查询主体有效权限集合",
            description = "格式: subject=user:UUID 或 subject=service_account:UUID")
    public ApiResults<Set<String>> permissions(
            @Parameter(description = "主体标识,格式 type:UUID",
                    required = true,
                    example = "user:00000000-0000-0000-0000-000000000000")
            @RequestParam("subject") String subject) {
        ParsedSubject p = parseSubject(subject);
        return ApiResults.success(decisionService.getEffectivePermissions(p.id, p.type));
    }

    /**
     * 解析 "type:UUID" 形式的 subject 参数。
     */
    private ParsedSubject parseSubject(String subject) {
        if (subject == null) {
            throw new IllegalArgumentException("subject 不能为空");
        }
        int idx = subject.indexOf(':');
        if (idx <= 0 || idx == subject.length() - 1) {
            throw new IllegalArgumentException(
                    "subject 格式必须为 type:UUID, 实际=" + subject);
        }
        String type = subject.substring(0, idx);
        String idStr = subject.substring(idx + 1);
        try {
            return new ParsedSubject(type, UUID.fromString(idStr));
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("subject UUID 格式不合法: " + idStr, ex);
        }
    }

    private record ParsedSubject(String type, UUID id) {
    }
}