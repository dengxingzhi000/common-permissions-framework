-- ======================================================================
-- V20260922_01__add_sys_tenant.sql
-- Phase 1.1 — Multi-tenancy foundation: sys_tenant table
-- ======================================================================
-- Backward-compatibility note:
--   * tenant_id columns on existing tables remain NULLABLE for now.
--   * A default tenant row is seeded at the bottom (tenant_code='default').
--   * Legacy single-tenant data can keep tenant_id NULL and continue to work.
-- ======================================================================

CREATE TABLE IF NOT EXISTS sys_tenant (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_code VARCHAR(64) NOT NULL UNIQUE,
    tenant_name VARCHAR(128) NOT NULL,
    status SMALLINT NOT NULL DEFAULT 1
        CONSTRAINT chk_tenant_status CHECK (status IN (0, 1)),
    isolation_level SMALLINT NOT NULL DEFAULT 1
        CONSTRAINT chk_isolation CHECK (isolation_level IN (1, 2, 3)),
    max_users INTEGER,
    expires_at TIMESTAMPTZ,
    contact_email VARCHAR(256),
    audit JSONB,
    create_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    update_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    create_by UUID,
    update_by UUID,
    deleted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_tenant_status ON sys_tenant(status) WHERE NOT deleted;

COMMENT ON TABLE sys_tenant IS '租户表 — Phase 1.1 多租户基础表';
COMMENT ON COLUMN sys_tenant.tenant_code IS '租户编码(全局唯一)';
COMMENT ON COLUMN sys_tenant.tenant_name IS '租户名称';
COMMENT ON COLUMN sys_tenant.status IS '状态:0-禁用,1-启用';
COMMENT ON COLUMN sys_tenant.isolation_level IS '隔离级别:1-共享,2-独立Schema,3-独立DB';
COMMENT ON COLUMN sys_tenant.max_users IS '用户上限(NULL表示不限制)';
COMMENT ON COLUMN sys_tenant.expires_at IS '到期时间(NULL表示永久)';
COMMENT ON COLUMN sys_tenant.audit IS '审计扩展字段(JSONB)';

-- 默认租户:用于兼容未迁移的存量数据(tenant_id IS NULL 也允许 NULL,这里只是种子示例)
INSERT INTO sys_tenant (tenant_code, tenant_name, isolation_level, contact_email)
VALUES ('default', '默认租户(legacy)', 1, '[email protected]')
ON CONFLICT (tenant_code) DO NOTHING;
