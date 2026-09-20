-- ======================================================================
-- 9. 用户直接权限授予表 (sys_user_permission) - 直接授权(永久)
-- 用于审批 type=2 (直接权限授予) 后的落库,与 sys_temp_permission 不同
-- 这里只保留永久直接授予;时间窗口(effective_time / expire_time)同时存在时
-- 视为临时直接授予 — 该约束由 chk_user_perm_time 强制。
-- ======================================================================
CREATE TABLE IF NOT EXISTS sys_user_permission (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    permission_id UUID NOT NULL REFERENCES sys_permission(id) ON DELETE CASCADE,
    effective_time TIMESTAMPTZ,
    expire_time TIMESTAMPTZ,
    granted_by UUID,
    grant_reason TEXT,
    create_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uk_user_permission UNIQUE (user_id, permission_id),
    CONSTRAINT chk_user_perm_time CHECK (
        (effective_time IS NULL AND expire_time IS NULL) OR
        (effective_time IS NOT NULL AND expire_time IS NOT NULL AND expire_time > effective_time)
    )
);

CREATE INDEX IF NOT EXISTS idx_user_perm_user ON sys_user_permission(user_id);
CREATE INDEX IF NOT EXISTS idx_user_perm_expire ON sys_user_permission(expire_time)
    WHERE expire_time IS NOT NULL;

COMMENT ON TABLE sys_user_permission IS '用户直接权限授予表(审批 type=2 落地)';
COMMENT ON COLUMN sys_user_permission.user_id IS '用户ID';
COMMENT ON COLUMN sys_user_permission.permission_id IS '权限ID(关联 sys_permission.id)';
COMMENT ON COLUMN sys_user_permission.granted_by IS '授权人ID';
COMMENT ON COLUMN sys_user_permission.grant_reason IS '授权原因';
