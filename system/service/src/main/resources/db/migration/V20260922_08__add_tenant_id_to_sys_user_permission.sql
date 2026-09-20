-- ======================================================================
-- V20260922_08__add_tenant_id_to_sys_user_permission.sql
-- Phase 1.2 — Add tenant_id to sys_user_permission.
--
-- New table introduced by Task 2.9 — Phase 1.2 brings it under tenant
-- scope in the same migration series.
-- ======================================================================

ALTER TABLE sys_user_permission ADD COLUMN IF NOT EXISTS tenant_id UUID;

CREATE INDEX IF NOT EXISTS idx_user_perm_tenant
    ON sys_user_permission(tenant_id)
    WHERE tenant_id IS NOT NULL;

COMMENT ON COLUMN sys_user_permission.tenant_id IS '租户ID(Phase 1.2; NULL 兼容 legacy)';
