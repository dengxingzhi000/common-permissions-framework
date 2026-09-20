-- ======================================================================
-- V20260922_02__add_sys_application.sql
-- Phase 1.1 — Multi-tenancy foundation: sys_application table
-- ======================================================================
-- A "tenant" owns one or more "applications". Applications are logical
-- groupings of permissions/resources (e.g., one application = one product
-- or system). tenant_id + app_code must be globally unique together.
-- ======================================================================

CREATE TABLE IF NOT EXISTS sys_application (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES sys_tenant(id) ON DELETE CASCADE,
    app_code VARCHAR(64) NOT NULL,
    app_name VARCHAR(128) NOT NULL,
    app_secret_hash VARCHAR(256),
    app_type SMALLINT NOT NULL DEFAULT 1
        CONSTRAINT chk_app_type CHECK (app_type IN (1, 2, 3)),
    redirect_uris TEXT[],
    scopes TEXT[],
    status SMALLINT NOT NULL DEFAULT 1,
    audit JSONB,
    create_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    update_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (tenant_id, app_code)
);

CREATE INDEX idx_app_tenant ON sys_application(tenant_id) WHERE NOT deleted;

COMMENT ON TABLE sys_application IS '应用表 — 隶属于 sys_tenant';
COMMENT ON COLUMN sys_application.tenant_id IS '租户ID';
COMMENT ON COLUMN sys_application.app_code IS '应用编码(租户内唯一)';
COMMENT ON COLUMN sys_application.app_name IS '应用名称';
COMMENT ON COLUMN sys_application.app_secret_hash IS '应用密钥哈希';
COMMENT ON COLUMN sys_application.app_type IS '应用类型:1-Web,2-Mobile,3-Service';
COMMENT ON COLUMN sys_application.redirect_uris IS 'OAuth2 redirect_uris';
COMMENT ON COLUMN sys_application.scopes IS 'OAuth2 scopes';
COMMENT ON COLUMN sys_application.status IS '状态:0-禁用,1-启用';
