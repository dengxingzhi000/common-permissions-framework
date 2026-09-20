package com.frog.common.tenant;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 租户配置 — {@code platform.tenant.*}。
 *
 * <p>通过 {@link TenantAutoConfiguration} 注册。
 *
 * @author Deng
 * @since 2026-09-22
 */
@Data
@ConfigurationProperties(prefix = "platform.tenant")
public class TenantProperties {

    /**
     * 是否启用租户隔离(true = 注入 tenant_id WHERE 条件)。
     */
    private boolean enabled = true;

    /**
     * 默认租户编码:当请求未携带 {@code X-Tenant-Id} 时使用。
     */
    private String defaultTenantCode = "default";

    /**
     * 严格模式:true 时,未携带 tenantId 的请求将被拒绝(抛业务异常)。
     * false 时,fallback 到默认租户。
     */
    private boolean strictMode = true;

    /**
     * HTTP header 名称:从中读取 tenantId 或 tenantCode。
     */
    private String headerName = "X-Tenant-Id";

    /**
     * 当请求中提供的是 tenantCode 而非 UUID 时,自动按编码查找。
     */
    private boolean resolveCodeToId = true;
}
