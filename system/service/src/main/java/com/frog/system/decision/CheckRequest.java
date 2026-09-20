package com.frog.system.decision;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;
import java.util.UUID;

/**
 * 授权决策请求 — DTO(Phase 1.8c)。
 *
 * <p>封装外部应用发起的"主体能否执行某动作?"问题。{@code subjectType} 与
 * {@code subjectId} 共同确定主体;{@code action} 是被请求的动作(可选);
 * {@code resourceType}/{@code resourceId} 用于资源作用域检查;{@code context}
 * 携带任意上下文(IP、时间、dept 等),供后续 ABAC 钩子使用。
 *
 * @author Deng
 * @since 2026-09-24
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "授权决策请求")
public class CheckRequest {

    @Schema(description = "主体类型: user | service_account")
    private String subjectType;

    @Schema(description = "主体ID")
    private UUID subjectId;

    @Schema(description = "被请求的动作(如 project.read / invoice.approve)")
    private String action;

    @Schema(description = "可选资源类型(与 scope 匹配)")
    private String resourceType;

    @Schema(description = "可选资源实例ID")
    private String resourceId;

    @Schema(description = "任意上下文(IP、时间、dept 等),供 ABAC 钩子使用")
    private Map<String, Object> context;
}