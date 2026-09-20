-- ======================================================================
-- V20260922_03__add_tenant_id_to_sys_user.sql
-- Phase 1.2 — Add tenant_id to sys_user.
--
-- Backward-compat decision (matches AGENTS.md commit strategy):
--   * Keep existing UNIQUE(username) for now — option (a) in the plan.
--     Rationale: avoids a destructive migration that would fail on existing
--     data when migrating into a multi-tenant schema. A follow-up migration
--     in Phase 1.4+ will swap to UNIQUE(tenant_id, username) once every
--     row has been backfilled.
--   * tenant_id is NULLABLE — legacy rows continue to work.
--   * A partial index on tenant_id accelerates tenant-scoped lookups.
-- ======================================================================

ALTER TABLE sys_user ADD COLUMN IF NOT EXISTS tenant_id UUID;

CREATE INDEX IF NOT EXISTS idx_user_tenant
    ON sys_user(tenant_id)
    WHERE NOT deleted AND tenant_id IS NOT NULL;

COMMENT ON COLUMN sys_user.tenant_id IS '租户ID(Phase 1.2 多租户隔离; NULL 兼容 legacy)';
