package com.frog.common.security.decision;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for {@link DecisionRecorder}.
 *
 * <p>When {@code enabled} is false, {@link DecisionRecorder#record(DecisionEvent)} is a no-op.
 * Persistence wiring (batch flush to {@code sys_decision_log}) lands in a later wave; the
 * current implementation buffers events in a {@link java.util.concurrent.ConcurrentLinkedQueue}.
 */
@Data
@ConfigurationProperties(prefix = "observability.decision-log")
public class DecisionRecorderProperties {
    private boolean enabled = true;
    private int batchSize = 100;
    private long flushIntervalMs = 1000;
}