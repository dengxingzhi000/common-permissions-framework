package com.frog.common.tenant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TenantSqlInterceptor unit tests — Phase 1.3.
 *
 * <p>Verifies SQL rewriting helpers (extractPrimaryTable, injectTenantFilter)
 * are correct. The full Interceptor chain requires a real StatementHandler;
 * see {@link com.frog.common.mybatisPlus.interceptor.DataScopeInterceptorTest}
 * for the established pattern of testing context-holder behavior separately.
 */
@DisplayName("TenantSqlInterceptor SQL Rewriting Tests")
class TenantSqlInterceptorTest {

    private final TenantSqlInterceptor interceptor = new TenantSqlInterceptor();

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    @DisplayName("extractPrimaryTable — simple FROM")
    void extractSimpleTable() {
        String sql = "SELECT id, username FROM sys_user WHERE status = 1";
        assertThat(interceptor.extractPrimaryTable(sql)).isEqualTo("sys_user");
    }

    @Test
    @DisplayName("extractPrimaryTable — schema-qualified")
    void extractSchemaQualified() {
        String sql = "SELECT id FROM db_user.sys_user WHERE status = 1";
        assertThat(interceptor.extractPrimaryTable(sql)).isEqualTo("sys_user");
    }

    @Test
    @DisplayName("extractPrimaryTable — no FROM returns null")
    void extractNoFrom() {
        assertThat(interceptor.extractPrimaryTable("SELECT 1")).isNull();
    }

    @Test
    @DisplayName("extractPrimaryTable — handles lowercase from")
    void extractLowerCase() {
        String sql = "select id from sys_role";
        assertThat(interceptor.extractPrimaryTable(sql)).isEqualTo("sys_role");
    }

    @Test
    @DisplayName("extractPrimaryTable — quoted identifier")
    void extractQuotedIdentifier() {
        String sql = "SELECT id FROM \"sys_permission\" WHERE NOT deleted";
        assertThat(interceptor.extractPrimaryTable(sql)).isEqualTo("sys_permission");
    }

    @Test
    @DisplayName("injectTenantFilter — appends WHERE when none exists")
    void injectAppendsWhere() {
        String sql = "SELECT id FROM sys_user";
        String result = interceptor.injectTenantFilter(sql);
        assertThat(result).contains("WHERE (tenant_id = #{__tenant_id}::uuid)");
    }

    @Test
    @DisplayName("injectTenantFilter — inserts filter into existing WHERE clause")
    void injectIntoExistingWhere() {
        String sql = "SELECT id FROM sys_user WHERE status = 1";
        String result = interceptor.injectTenantFilter(sql);
        assertThat(result).contains("WHERE (tenant_id = #{__tenant_id}::uuid) AND (status = 1)");
    }

    @Test
    @DisplayName("injectTenantFilter — strips trailing semicolon before appending WHERE")
    void injectStripsSemicolon() {
        String sql = "SELECT id FROM sys_user;";
        String result = interceptor.injectTenantFilter(sql);
        assertThat(result).endsWith("WHERE (tenant_id = #{__tenant_id}::uuid)");
        assertThat(result).doesNotContain(";");
    }

    @Test
    @DisplayName("injectTenantFilter — uses parameter placeholder (no string concat of values)")
    void injectUsesPlaceholder() {
        UUID tid = UUID.randomUUID();
        TenantContext.set(tid);

        String result = interceptor.injectTenantFilter("SELECT id FROM sys_user");

        // The placeholder is the only safe binding path — verify the literal
        // tenantId UUID is NOT concatenated into the SQL string.
        assertThat(result).contains("#{__tenant_id}");
        assertThat(result).doesNotContain(tid.toString());
    }
}
