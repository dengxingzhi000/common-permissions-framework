-- ======================================================================
-- V20260924_02__add_sys_grant.sql
-- Phase 1 / Item 1.8a — Grant entity
-- ======================================================================
-- A single canonical authorization tuple that subsumes role-grants and
-- direct-grants. Each row links a Subject (user | service_account) to a
-- Target (role | permission | resource) with explicit effect, scope, and
-- priority. Evaluation (deny-overrides, higher priority wins) is implemented
-- in com.frog.system.decision.DecisionServiceImpl.
--
-- `target_id` semantics depend on `target_type`:
--   - 'role'        → sys_role.id
--   - 'permission'  → sys_permission.id (UUID)
--   - 'resource'    → sys_resource.id (UUID)
--
-- The `action` field applies only when target_type='permission' or
-- 'resource'; for role-grants, action filtering happens after expansion.
-- ======================================================================

CREATE TABLE IF NOT EXISTS sys_grant (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES sys_tenant(id) ON DELETE CASCADE,
    app_id UUID REFERENCES sys_application(id) ON DELETE CASCADE,
    subject_type VARCHAR(32) NOT NULL,
    subject_id UUID NOT NULL,
    target_type VARCHAR(32) NOT NULL,
    target_id UUID NOT NULL,
    action VARCHAR(128),
    resource_type_filter VARCHAR(64),
    effect VARCHAR(16) NOT NULL DEFAULT 'allow'
        CONSTRAINT chk_grant_effect CHECK (effect IN ('allow', 'deny')),
    priority INTEGER NOT NULL DEFAULT 100,
    scope_org_id UUID,
    scope_resource_id VARCHAR(256),
    effective_time TIMESTAMPTZ,
    expire_time TIMESTAMPTZ,
    granted_by UUID,
    grant_reason TEXT,
    audit JSONB,
    create_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    update_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT chk_grant_time CHECK (
        effective_time IS NULL OR expire_time IS NULL OR expire_time > effective_time
    )
);

CREATE INDEX idx_grant_subject ON sys_grant(subject_type, subject_id) WHERE NOT deleted;
CREATE INDEX idx_grant_target ON sys_grant(target_type, target_id) WHERE NOT deleted;
CREATE INDEX idx_grant_tenant_app ON sys_grant(tenant_id, app_id) WHERE NOT deleted;
CREATE INDEX idx_grant_active ON sys_grant(expire_time) WHERE expire_time IS NOT NULL AND NOT deleted;

COMMENT ON TABLE sys_grant IS '授权实体 — 统一角色授权与直接授权(Phase 1.8a)';
COMMENT ON COLUMN sys_grant.subject_type IS '主体类型: user | service_account';
COMMENT ON COLUMN sys_grant.subject_id IS '主体ID';
COMMENT ON COLUMN sys_grant.target_type IS '目标类型: role | permission | resource';
COMMENT ON COLUMN sys_grant.target_id IS '目标ID(角色/权限/资源)';
COMMENT ON COLUMN sys_grant.action IS '动作(如 project.read),对 permission/resource 类型生效';
COMMENT ON COLUMN sys_grant.resource_type_filter IS '可选资源类型约束';
COMMENT ON COLUMN sys_grant.effect IS '效果: allow | deny';
COMMENT ON COLUMN sys_grant.priority IS '优先级,数值越大越优先;deny 在同优先级压倒 allow';
COMMENT ON COLUMN sys_grant.scope_org_id IS '可选部门/组织范围';
COMMENT ON COLUMN sys_grant.scope_resource_id IS '可选特定资源实例范围';
COMMENT ON COLUMN sys_grant.effective_time IS '生效时间,NULL 表示即时生效';
COMMENT ON COLUMN sys_grant.expire_time IS '过期时间,NULL 表示永不过期';