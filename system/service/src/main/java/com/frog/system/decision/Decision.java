package com.frog.system.decision;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

/**
 * 授权决策结果 — DTO(Phase 1.8c)。
 *
 * <p>决策评估的最终输出。{@code decisionId} 是本次评估的唯一标识,会被
 * 写入 {@code sys_decision_log};{@code policyVersion} 是评估时引用的
 * 策略版本号(来自 {@code sys_policy_version WHERE status='active'})。
 *
 * @author Deng
 * @since 2026-09-24
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "授权决策结果")
public class Decision {

    @Schema(description = "效果: allow | deny")
    private String effect;

    @Schema(description = "人类可读的决策原因(如 'role X grants permission Y' / 'no grants match')")
    private String reason;

    @Schema(description = "评估时引用的策略版本号")
    private String policyVersion;

    @Schema(description = "本次决策的唯一标识(UUID),用于审计追溯")
    private UUID decisionId;

    @Schema(description = "评估耗时(毫秒)")
    private long latencyMs;
}