-- ======================================================================
-- V20260923_01__add_sys_registered_client.sql
-- Phase 1.4 — Per-tenant DB-backed RegisteredClient
-- ======================================================================
-- Replaces the hard-coded InMemoryRegisteredClientRepository in
-- com.frog.common.uaa.config.AuthorizationServerConfig (lines 118-178).
-- Each tenant can register one or more OAuth2 clients. application_id
-- is a logical FK to sys_application.id (SET NULL on delete so the
-- client outlives a deleted app record).
--
-- Backward compatibility:
--   * No data is backfilled; the hard-coded web/mobile/service clients
--     must be manually inserted as rows before first deploy.
--   * status CHECK ensures only 0/1 values.
-- ======================================================================

CREATE TABLE IF NOT EXISTS sys_registered_client (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES sys_tenant(id) ON DELETE CASCADE,
    application_id UUID REFERENCES sys_application(id) ON DELETE SET NULL,
    client_id VARCHAR(128) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(256),
    client_auth_methods TEXT[] NOT NULL DEFAULT '{client_secret_basic}',
    grant_types TEXT[] NOT NULL DEFAULT '{authorization_code}',
    redirect_uris TEXT[],
    post_logout_redirect_uris TEXT[],
    scopes TEXT[] NOT NULL DEFAULT '{}',
    require_authorization_consent BOOLEAN NOT NULL DEFAULT FALSE,
    require_proof_key BOOLEAN NOT NULL DEFAULT FALSE,
    access_token_ttl_seconds INTEGER NOT NULL DEFAULT 7200,
    refresh_token_ttl_seconds INTEGER NOT NULL DEFAULT 604800,
    status SMALLINT NOT NULL DEFAULT 1
        CONSTRAINT chk_client_status CHECK (status IN (0, 1)),
    audit JSONB,
    create_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    update_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_client_tenant ON sys_registered_client(tenant_id) WHERE NOT deleted;

COMMENT ON TABLE sys_registered_client IS 'OAuth2 注册客户端表 — Phase 1.4 多租户';
COMMENT ON COLUMN sys_registered_client.tenant_id IS '租户ID';
COMMENT ON COLUMN sys_registered_client.application_id IS '应用ID(逻辑外键,可空)';
COMMENT ON COLUMN sys_registered_client.client_id IS 'OAuth2 client_id(全局唯一)';
COMMENT ON COLUMN sys_registered_client.client_secret_hash IS 'client_secret BCrypt 哈希';
COMMENT ON COLUMN sys_registered_client.client_auth_methods IS '客户端认证方式';
COMMENT ON COLUMN sys_registered_client.grant_types IS '授权类型';
COMMENT ON COLUMN sys_registered_client.redirect_uris IS 'OAuth2 redirect_uris';
COMMENT ON COLUMN sys_registered_client.post_logout_redirect_uris IS '登出后跳转 URI';
COMMENT ON COLUMN sys_registered_client.scopes IS 'OAuth2 scopes';
COMMENT ON COLUMN sys_registered_client.require_authorization_consent IS '是否需要授权确认';
COMMENT ON COLUMN sys_registered_client.require_proof_key IS '是否强制 PKCE';
COMMENT ON COLUMN sys_registered_client.access_token_ttl_seconds IS 'Access Token 有效期(秒)';
COMMENT ON COLUMN sys_registered_client.refresh_token_ttl_seconds IS 'Refresh Token 有效期(秒)';
COMMENT ON COLUMN sys_registered_client.status IS '状态:0-禁用,1-启用';
