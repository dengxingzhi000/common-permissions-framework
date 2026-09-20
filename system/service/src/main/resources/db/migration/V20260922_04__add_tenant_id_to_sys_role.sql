-- ======================================================================
-- V20260922_04__add_tenant_id_to_sys_role.sql
-- Phase 1.2 — Add tenant_id to sys_role.
--
-- Note: existing UNIQUE(role_code) is preserved for backward compat
-- (option (a)). role_code+tenant_id will become the unique constraint in
-- a follow-up migration after legacy data is backfilled.
-- ======================================================================

ALTER TABLE sys_role ADD COLUMN IF NOT EXISTS tenant_id UUID;

CREATE INDEX IF NOT EXISTS idx_role_tenant
    ON sys_role(tenant_id)
    WHERE NOT deleted AND tenant_id IS NOT NULL;

COMMENT ON COLUMN sys_role.tenant_id IS '租户ID(Phase 1.2; NULL 兼容 legacy)';
