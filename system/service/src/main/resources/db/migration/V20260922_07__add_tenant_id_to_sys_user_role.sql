-- ======================================================================
-- V20260922_07__add_tenant_id_to_sys_user_role.sql
-- Phase 1.2 — Add tenant_id to sys_user_role.
--
-- user_role is a relationship row; tenant_id lets the join tables be
-- filtered independently of sys_user / sys_role rows.
-- ======================================================================

ALTER TABLE sys_user_role ADD COLUMN IF NOT EXISTS tenant_id UUID;

CREATE INDEX IF NOT EXISTS idx_user_role_tenant
    ON sys_user_role(tenant_id)
    WHERE tenant_id IS NOT NULL;

COMMENT ON COLUMN sys_user_role.tenant_id IS '租户ID(Phase 1.2; NULL 兼容 legacy)';
