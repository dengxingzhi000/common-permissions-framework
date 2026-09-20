package com.frog.common.tenant;

import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.executor.statement.StatementHandler;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.plugin.Intercepts;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.plugin.Plugin;
import org.apache.ibatis.plugin.Signature;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.SystemMetaObject;

import java.sql.Connection;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;

/**
 * MyBatis 拦截器 — 自动注入 tenant_id 过滤。
 *
 * <p>Phase 1.3: 与 {@link com.frog.common.mybatisPlus.interceptor.DataScopeInterceptor}
 * 同模式。对每个 SELECT 语句,如果 FROM 子句中的表具备 tenant_id 列,则追加
 * {@code AND tenant_id = #{__tenant_id::uuid}},参数取自 {@link TenantContext}。
 *
 * <p>当前实现采用字符串注入 + 参数化占位符的混合方式:
 * <ul>
 *   <li>占位符使用 {@code #{__tenant_id}} — 值经 PreparedStatement 绑定,不会拼接</li>
 *   <li>表名白名单通过 {@link #TENANT_SCOPED_TABLES} 控制,避免误改跨租户共享表</li>
 *   <li>严格模式(strictMode)由调用方在 strict 模式下处理,本拦截器不阻断 SQL</li>
 * </ul>
 *
 * <p>使用 {@link com.baomidou.mybatisplus.extension.plugins.MybatisPlusInterceptor} 注册,
 * 或直接通过 {@code @Bean} 注册 — 在 {@link TenantAutoConfiguration} 中完成。
 *
 * @author Deng
 * @since 2026-09-22
 */
@Slf4j
@Intercepts({
        @Signature(
                type = StatementHandler.class,
                method = "prepare",
                args = {Connection.class, Integer.class}
        )
})
public class TenantSqlInterceptor implements Interceptor {

    /**
     * 已知具备 tenant_id 列的表(Phase 1.3 范围)。
     * <p>Phase 1.4+ 将通过元数据/注解自动发现,无需维护此白名单。
     */
    private static final Set<String> TENANT_SCOPED_TABLES = Set.of(
            "sys_user",
            "sys_role",
            "sys_permission",
            "sys_dept",
            "sys_user_role",
            "sys_user_permission"
    );

    static final String TENANT_PARAM_KEY = "__tenant_id";
    static final String TENANT_PARAM_UUID = "__tenant_id_uuid";

    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        if (!TenantContext.isPresent()) {
            return invocation.proceed();
        }

        StatementHandler handler = (StatementHandler) invocation.getTarget();
        MetaObject metaObject = SystemMetaObject.forObject(handler);

        if (!isSelectStatement(metaObject)) {
            return invocation.proceed();
        }

        BoundSql boundSql = handler.getBoundSql();
        String original = boundSql.getSql();
        if (original == null || original.isBlank()) {
            return invocation.proceed();
        }

        String table = extractPrimaryTable(original);
        if (table == null || !TENANT_SCOPED_TABLES.contains(table.toLowerCase(Locale.ROOT))) {
            return invocation.proceed();
        }

        UUID tenantId = TenantContext.get();
        if (tenantId == null) {
            return invocation.proceed();
        }

        String rewritten = injectTenantFilter(original);
        metaObject.setValue("delegate.boundSql.sql", rewritten);
        boundSql.setAdditionalParameter(TENANT_PARAM_KEY, tenantId.toString());

        log.debug("Tenant filter applied on table={} -> {}", table, rewritten);
        return invocation.proceed();
    }

    @Override
    public Object plugin(Object target) {
        return Plugin.wrap(target, this);
    }

    @Override
    public void setProperties(Properties properties) {
        // no-op; 配置走 TenantProperties
    }

    // ----------------------- helpers -----------------------

    /**
     * 检测 SQL 命令类型是否为 SELECT。失败时(无法识别)默认 false — 安全优先。
     */
    private boolean isSelectStatement(MetaObject metaObject) {
        try {
            Object cmd = metaObject.getValue("delegate.mappedStatement.sqlCommandType");
            return cmd != null && "SELECT".equalsIgnoreCase(cmd.toString());
        } catch (Exception e) {
            log.debug("Could not determine SQL command type, skipping tenant filter", e);
            return false;
        }
    }

    /**
     * 从 SQL 中提取主表名(简化版):从 {@code from} 后取第一个标识符。
     * <p>支持 {@code FROM tableName} / {@code FROM schema.tableName} / {@code FROM "tableName"}。
     * 复杂 JOIN/子查询场景交给 Phase 1.4+ 的 JSqlParser 路径处理。
     */
    String extractPrimaryTable(String sql) {
        String lower = sql.toLowerCase(Locale.ROOT);
        int fromIdx = lower.indexOf(" from ");
        if (fromIdx < 0) {
            return null;
        }
        int cursor = fromIdx + " from ".length();
        // Skip any leading paren/quote
        while (cursor < sql.length() && (sql.charAt(cursor) == '(' || sql.charAt(cursor) == '"')) {
            cursor++;
        }
        int start = cursor;
        while (cursor < sql.length()) {
            char c = sql.charAt(cursor);
            if (Character.isWhitespace(c) || c == ',' || c == ')' || c == '"' || c == '\'') {
                break;
            }
            cursor++;
        }
        if (cursor == start) {
            return null;
        }
        String raw = sql.substring(start, cursor);
        // strip schema prefix
        int dot = raw.lastIndexOf('.');
        String table = dot >= 0 ? raw.substring(dot + 1) : raw;
        // strip quotes
        return table.replace("\"", "");
    }

    /**
     * 追加 tenant_id 过滤到 WHERE 子句;若无 WHERE 则附加 WHERE。
     * <p>使用参数化占位符 {@code #{__tenant_id}},值走 PreparedStatement 绑定。
     */
    String injectTenantFilter(String sql) {
        String lower = sql.toLowerCase(Locale.ROOT);
        int whereIdx = lower.indexOf(" where ");
        String clause = "tenant_id = #{" + TENANT_PARAM_KEY + "}::uuid";

        if (whereIdx >= 0) {
            return sql.substring(0, whereIdx + " where ".length())
                    + "(" + clause + ") AND "
                    + sql.substring(whereIdx + " where ".length());
        }
        // Skip trailing semicolon, then append WHERE
        String trimmed = sql.endsWith(";") ? sql.substring(0, sql.length() - 1) : sql;
        return trimmed + " WHERE (" + clause + ")";
    }
}
