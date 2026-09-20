-- ======================================================================
-- V20260924_01__add_sys_resource.sql
-- Phase 1 / Item 1.7 — Resource catalog: sys_resource table
-- ======================================================================
-- A typed Resource registry. Replaces the stringly-typed
-- `sys_data_permission_rule.resource_type VARCHAR(50)` with a first-class
-- FK-targetable catalog. Each resource is scoped to (tenant_id, app_id)
-- and identified by a stable `resource_code` (e.g. "PROJECT", "INVOICE").
--
-- `parent_id` enables a tree structure for resources that have a natural
-- hierarchy (e.g. PROJECT > MILESTONE > TASK). `metadata` JSONB carries
-- arbitrary per-resource-type attributes (without polluting the column set).
-- ======================================================================

CREATE TABLE IF NOT EXISTS sys_resource (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES sys_tenant(id) ON DELETE CASCADE,
    app_id UUID REFERENCES sys_application(id) ON DELETE CASCADE,
    resource_code VARCHAR(128) NOT NULL,
    resource_name VARCHAR(256) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    parent_id UUID REFERENCES sys_resource(id) ON DELETE SET NULL,
    description TEXT,
    metadata JSONB,
    status SMALLINT NOT NULL DEFAULT 1,
    audit JSONB,
    create_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    update_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (tenant_id, app_id, resource_code)
);

CREATE INDEX idx_resource_type ON sys_resource(resource_type) WHERE NOT deleted;
CREATE INDEX idx_resource_tenant_app ON sys_resource(tenant_id, app_id) WHERE NOT deleted;

COMMENT ON TABLE sys_resource IS '资源目录 — 替换 stringly-typed resource_type(Phase 1.7)';
COMMENT ON COLUMN sys_resource.tenant_id IS '租户ID';
COMMENT ON COLUMN sys_resource.app_id IS '应用ID';
COMMENT ON COLUMN sys_resource.resource_code IS '资源编码(租户+应用内唯一)';
COMMENT ON COLUMN sys_resource.resource_name IS '资源名称';
COMMENT ON COLUMN sys_resource.resource_type IS '资源类型(例如 PROJECT / DOCUMENT / INVOICE)';
COMMENT ON COLUMN sys_resource.parent_id IS '父资源ID,用于资源树';
COMMENT ON COLUMN sys_resource.metadata IS '扩展元数据(JSONB)';
COMMENT ON COLUMN sys_resource.status IS '状态:0-禁用,1-启用';