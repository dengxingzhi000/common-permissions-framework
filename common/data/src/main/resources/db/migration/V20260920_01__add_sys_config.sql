CREATE TABLE IF NOT EXISTS sys_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key VARCHAR(128) NOT NULL,
    config_value TEXT NOT NULL,
    scope VARCHAR(32) NOT NULL DEFAULT 'GLOBAL',
    tenant_id UUID,
    description TEXT,
    status SMALLINT NOT NULL DEFAULT 1,
    create_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    update_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uk_config_key_tenant UNIQUE (config_key, tenant_id),
    CONSTRAINT chk_config_scope CHECK (scope IN ('GLOBAL', 'TENANT'))
);

CREATE INDEX IF NOT EXISTS idx_config_scope ON sys_config(scope);

COMMENT ON TABLE sys_config IS '平台配置表(替代硬编码常量)';

INSERT INTO sys_config (config_key, config_value, description) VALUES
    ('super_admin_user_id', '019a0aee-3b74-7bfc-b34f-48b5428d4875', 'Built-in super admin user UUID (legacy)'),
    ('super_admin_role_id', '019a0aee-3b74-7bfc-b34f-48b5428d4875', 'Built-in super admin role UUID (legacy)')
ON CONFLICT (config_key, tenant_id) DO NOTHING;