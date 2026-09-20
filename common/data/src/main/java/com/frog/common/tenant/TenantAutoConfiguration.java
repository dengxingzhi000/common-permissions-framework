package com.frog.common.tenant;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * 多租户自动配置。
 *
 * <p>Phase 1.3 暴露的 beans:
 * <ul>
 *   <li>{@link TenantContextFilter} — servlet 过滤器(由 {@code @Component} 注解自动注册,
 *       此处仅作条件化提示)</li>
 *   <li>{@link TenantSqlInterceptor} — MyBatis 拦截器</li>
 *   <li>{@link TenantContextWebFilter} — WebFlux 过滤器(仅在 gateway 引入)</li>
 * </ul>
 *
 * <p>启用条件: {@code platform.tenant.enabled=true}(默认)。
 * 若 {@code platform.tenant.enabled=false},所有 bean 都不会创建,等同于多租户未启用。
 *
 * @author Deng
 * @since 2026-09-22
 */
@Slf4j
@AutoConfiguration
@EnableConfigurationProperties(TenantProperties.class)
@ConditionalOnProperty(prefix = "platform.tenant", name = "enabled", havingValue = "true", matchIfMissing = true)
public class TenantAutoConfiguration {

    /**
     * MyBatis 拦截器 — 自动注入 tenant_id WHERE 条件。
     */
    @Bean
    @ConditionalOnClass(name = "org.apache.ibatis.plugin.Interceptor")
    @ConditionalOnMissingBean(TenantSqlInterceptor.class)
    public TenantSqlInterceptor tenantSqlInterceptor() {
        log.info("[Tenant] Registering TenantSqlInterceptor");
        return new TenantSqlInterceptor();
    }

    /**
     * WebFlux 过滤器 — Gateway 端 tenantId 解析。
     * <p>仅当 webflux 在 classpath 时创建。Servlet 链通过 {@link TenantContextFilter} 处理。
     */
    @Bean
    @ConditionalOnClass(name = "org.springframework.web.server.WebFilter")
    @ConditionalOnMissingBean(TenantContextWebFilter.class)
    public TenantContextWebFilter tenantContextWebFilter(TenantProperties properties) {
        log.info("[Tenant] Registering TenantContextWebFilter (WebFlux)");
        return new TenantContextWebFilter(properties);
    }
}
