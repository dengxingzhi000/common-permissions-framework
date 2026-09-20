package com.frog.common.security.decision;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * In-memory buffer for {@link DecisionEvent}s.
 *
 * <p>Stub for Phase 0 / Item 0.10: events are appended to a
 * {@link ConcurrentLinkedQueue} and {@link #flush()} is currently a no-op
 * aside from clearing the buffer. Persistence to {@code sys_decision_log}
 * is wired in a later wave (Item 0.10b).
 *
 * <p>Designed to be safe to call from request-scoped filters and the
 * permission evaluator without throwing on configuration issues.
 */
@Slf4j
@RequiredArgsConstructor
public class DecisionRecorder {

    private final DecisionRecorderProperties properties;
    private final ConcurrentLinkedQueue<DecisionEvent> buffer = new ConcurrentLinkedQueue<>();

    public void record(DecisionEvent event) {
        if (event == null) {
            return;
        }
        if (!properties.isEnabled()) {
            return;
        }
        buffer.add(event);
        if (buffer.size() >= properties.getBatchSize()) {
            flush();
        }
    }

    public synchronized void flush() {
        if (buffer.isEmpty()) {
            return;
        }
        int n = buffer.size();
        log.debug("DecisionRecorder flushing {} events (no-op without persistence wiring yet)", n);
        buffer.clear();
    }

    public int bufferedCount() {
        return buffer.size();
    }
}