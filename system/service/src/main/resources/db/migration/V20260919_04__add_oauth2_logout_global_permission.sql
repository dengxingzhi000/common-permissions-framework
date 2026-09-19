-- ======================================================================
-- Seed permission: oauth2:logout:global
-- Refactor: OAuth2LogoutController global revocation requires this authority
-- ======================================================================

INSERT INTO sys_permission (id, permission_code, permission_name, permission_type,
                            permission_level, risk_level, need_approval, need_two_factor,
                            visible, status, sort_order, create_time, update_time, deleted)
VALUES (gen_random_uuid(), 'oauth2:logout:global', 'OAuth2 全局登出', 3,
        1, 3, FALSE, FALSE, TRUE, 1, 100, NOW(), NOW(), FALSE)
ON CONFLICT (permission_code) DO NOTHING;

-- Grant to ROLE_SUPER_ADMIN (project convention; RoleDTO enforces ^ROLE_[A-Z_]+$).
INSERT INTO sys_role_permission (id, role_id, permission_id, create_time, create_by)
SELECT gen_random_uuid(), r.id, p.id, NOW(), NULL
FROM sys_role r, sys_permission p
WHERE r.role_code = 'ROLE_SUPER_ADMIN'
  AND p.permission_code = 'oauth2:logout:global'
ON CONFLICT DO NOTHING;