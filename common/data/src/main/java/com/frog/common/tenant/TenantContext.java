package com.frog.common.tenant;

import java.util.UUID;

/**
 * 租户上下文 — ThreadLocal 持有当前请求线程的 tenantId。
 *
 * <p>Phase 1.3: 与 {@link com.frog.common.mybatisPlus.context.DataScopeContextHolder}
 * 同样的模式。{@link TenantContextFilter} 在请求进入时 {@code set},返回时 {@code clear}。
 * {@link TenantSqlInterceptor} 在每次 SELECT 时读取并注入 WHERE 条件。
 *
 * <p>使用规范:
 * <ul>
 *   <li>永远在 finally 中调用 {@link #clear()},防止线程复用时数据泄露</li>
 *   <li>异步任务中需要重新 {@link #set(UUID)},ThreadLocal 不会跨线程传递</li>
 * </ul>
 *
 * @author Deng
 * @since 2026-09-22
 */
public final class TenantContext {

    private static final ThreadLocal<UUID> CURRENT = new ThreadLocal<>();

    private TenantContext() {
    }

    /**
     * 设置当前线程的 tenantId。
     */
    public static void set(UUID tenantId) {
        CURRENT.set(tenantId);
    }

    /**
     * 读取当前线程的 tenantId;若未设置则返回 {@code null}。
     */
    public static UUID get() {
        return CURRENT.get();
    }

    /**
     * 清除当前线程的 tenantId。必须在线程归还线程池前调用。
     */
    public static void clear() {
        CURRENT.remove();
    }

    /**
     * 检查当前是否绑定了 tenantId。
     */
    public static boolean isPresent() {
        return CURRENT.get() != null;
    }
}
