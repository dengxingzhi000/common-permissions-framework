-- ======================================================================
-- V20260924_03__add_sys_policy_version.sql
-- Phase 1 / Item 1.8b — Policy versioning
-- ======================================================================
-- Tracks versions of authorization policy snapshots. Each row represents
-- one published version; `policy_snapshot` freezes the role-permission
-- mapping and grant set at activation time so decision evaluation can
-- optionally be replayed or audited against a historical policy.
--
-- Only one row per (tenant_id, app_id, status='active') tuple should be
-- marked active at a time; the unique-on-version constraint ensures
-- version labels are globally unique across the platform.
-- ======================================================================

CREATE TABLE IF NOT EXISTS sys_policy_version (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version VARCHAR(32) NOT NULL UNIQUE,
    tenant_id UUID REFERENCES sys_tenant(id) ON DELETE CASCADE,
    app_id UUID REFERENCES sys_application(id) ON DELETE CASCADE,
    description TEXT,
    policy_snapshot JSONB,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_by UUID,
    status VARCHAR(16) NOT NULL DEFAULT 'active'
        CONSTRAINT chk_policy_status CHECK (status IN ('draft', 'active', 'archived')),
    create_time TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policy_tenant_status ON sys_policy_version(tenant_id, status);

COMMENT ON TABLE sys_policy_version IS '策略版本表 — 冻结每次发布的授权快照(Phase 1.8b)';
COMMENT ON COLUMN sys_policy_version.version IS '版本标签(全局唯一,如 v20260924-001)';
COMMENT ON COLUMN sys_policy_version.policy_snapshot IS '冻结的策略快照(角色权限+授权集)';
COMMENT ON COLUMN sys_policy_version.activated_at IS '激活时间';
COMMENT ON COLUMN sys_policy_version.activated_by IS '激活人';
COMMENT ON COLUMN sys_policy_version.status IS '状态: draft | active | archived';