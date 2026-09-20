CREATE TABLE IF NOT EXISTS sys_decision_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    decision_id UUID NOT NULL UNIQUE,
    create_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    subject_type VARCHAR(32) NOT NULL,
    subject_id UUID NOT NULL,
    action VARCHAR(128) NOT NULL,
    resource_type VARCHAR(64),
    resource_id VARCHAR(256),
    context JSONB,
    effect VARCHAR(16) NOT NULL,
    reason TEXT,
    policy_version VARCHAR(32),
    request_id VARCHAR(64),
    latency_ms INTEGER NOT NULL,
    source_module VARCHAR(64),
    CONSTRAINT chk_decision_effect CHECK (effect IN ('allow', 'deny'))
) PARTITION BY RANGE (create_time);

CREATE INDEX IF NOT EXISTS idx_decision_subject ON sys_decision_log(subject_id, create_time DESC);
CREATE INDEX IF NOT EXISTS idx_decision_action ON sys_decision_log(action, create_time DESC);
CREATE INDEX IF NOT EXISTS idx_decision_effect ON sys_decision_log(effect, create_time DESC);

CREATE TABLE IF NOT EXISTS sys_decision_log_default PARTITION OF sys_decision_log DEFAULT;