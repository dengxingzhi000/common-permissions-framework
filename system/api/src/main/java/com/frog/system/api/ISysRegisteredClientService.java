package com.frog.system.api;

import com.frog.system.domain.entity.SysRegisteredClient;

import java.util.Optional;
import java.util.UUID;

/**
 * SysRegisteredClient 服务接口 — Phase 1.4。
 *
 * <p>放在 {@code system/api} 模块,而不是 {@code system/service},
 * 以便 {@code common/web} 中的 {@code TenantRegisteredClientRepository}
 * 能直接引用本接口而不破坏模块依赖方向(
 * {@code common/*} MUST NOT depend on {@code system/service})。
 *
 * <p>Dubbo 调用方通过 {@code @DubboReference} 获取代理;
 * Spring 直接调用方通过构造函数注入。
 *
 * @author Deng
 * @since 2026-09-23
 */
public interface ISysRegisteredClientService {

    /**
     * 根据 OAuth2 client_id 查询客户端记录(全局唯一)。
     *
     * <p>不抛异常,未找到时返回 {@link Optional#empty()}。
     */
    Optional<SysRegisteredClient> findOptionalByClientId(String clientId);

    /**
     * 根据 OAuth2 client_id 查询;未找到返回 {@code null}。
     */
    SysRegisteredClient findByClientId(String clientId);

    /**
     * 根据租户 ID + client_id 查询。
     */
    SysRegisteredClient findByTenantAndClientId(UUID tenantId, String clientId);

    /**
     * 新增客户端。
     */
    SysRegisteredClient addClient(SysRegisteredClient client);

    /**
     * 修改客户端。
     */
    SysRegisteredClient updateClient(SysRegisteredClient client);

    /**
     * 软删除客户端。
     */
    void deleteClient(UUID id);
}
