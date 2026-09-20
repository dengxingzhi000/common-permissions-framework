-- ======================================================================
-- V20260922_05__add_tenant_id_to_sys_permission.sql
-- Phase 1.2 — Add tenant_id to sys_permission.
-- ======================================================================

ALTER TABLE sys_permission ADD COLUMN IF NOT EXISTS tenant_id UUID;

CREATE INDEX IF NOT EXISTS idx_permission_tenant
    ON sys_permission(tenant_id)
    WHERE NOT deleted AND tenant_id IS NOT NULL;

COMMENT ON COLUMN sys_permission.tenant_id IS '租户ID(Phase 1.2; NULL 兼容 legacy)';
