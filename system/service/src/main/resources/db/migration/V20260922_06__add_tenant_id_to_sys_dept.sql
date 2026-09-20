-- ======================================================================
-- V20260922_06__add_tenant_id_to_sys_dept.sql
-- Phase 1.2 — Add tenant_id to sys_dept.
-- ======================================================================

ALTER TABLE sys_dept ADD COLUMN IF NOT EXISTS tenant_id UUID;

CREATE INDEX IF NOT EXISTS idx_dept_tenant
    ON sys_dept(tenant_id)
    WHERE NOT deleted AND tenant_id IS NOT NULL;

COMMENT ON COLUMN sys_dept.tenant_id IS '租户ID(Phase 1.2; NULL 兼容 legacy)';
