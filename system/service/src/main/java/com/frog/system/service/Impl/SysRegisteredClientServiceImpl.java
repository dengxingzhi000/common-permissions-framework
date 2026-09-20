package com.frog.system.service.Impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.frog.common.exception.BusinessException;
import com.frog.common.util.UUIDv7Util;
import com.frog.system.api.ISysRegisteredClientService;
import com.frog.system.domain.entity.SysRegisteredClient;
import com.frog.system.mapper.SysRegisteredClientMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.dubbo.config.annotation.DubboService;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * SysRegisteredClient 服务实现 — sys_registered_client。
 *
 * <p>实现 {@link ISysRegisteredClientService},该接口位于
 * {@code system/api} 模块,便于 {@code common/web} 引用。
 *
 * <p>同时暴露为 Dubbo 服务,供跨进程消费方(如 {@code auth} 模块的
 * {@code AuthorizationServerConfig})通过 {@code @DubboReference} 注入。
 *
 * @author Deng
 * @since 2026-09-23
 */
@Service
@DubboService
@RequiredArgsConstructor
@Slf4j
public class SysRegisteredClientServiceImpl
        extends ServiceImpl<SysRegisteredClientMapper, SysRegisteredClient>
        implements ISysRegisteredClientService {

    private final SysRegisteredClientMapper clientMapper;

    @Override
    public Optional<SysRegisteredClient> findOptionalByClientId(String clientId) {
        return clientMapper.findOptionalByClientId(clientId);
    }

    @Override
    public SysRegisteredClient findByClientId(String clientId) {
        return clientMapper.findByClientId(clientId);
    }

    @Override
    public SysRegisteredClient findByTenantAndClientId(UUID tenantId, String clientId) {
        return clientMapper.findByTenantAndClientId(tenantId, clientId);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "registeredClient", allEntries = true)
    public SysRegisteredClient addClient(SysRegisteredClient client) {
        if (client.getTenantId() == null) {
            throw new BusinessException("租户ID不能为空");
        }
        if (client.getClientId() == null || client.getClientId().isBlank()) {
            throw new BusinessException("client_id 不能为空");
        }
        if (clientMapper.findByClientId(client.getClientId()) != null) {
            throw new BusinessException("client_id 已存在(全局唯一): " + client.getClientId());
        }
        if (client.getId() == null) {
            client.setId(UUIDv7Util.generate());
        }
        if (client.getStatus() == null) {
            client.setStatus(1);
        }
        if (client.getAccessTokenTtlSeconds() == null) {
            client.setAccessTokenTtlSeconds(7200);
        }
        if (client.getRefreshTokenTtlSeconds() == null) {
            client.setRefreshTokenTtlSeconds(604800);
        }
        if (client.getRequireAuthorizationConsent() == null) {
            client.setRequireAuthorizationConsent(false);
        }
        if (client.getRequireProofKey() == null) {
            client.setRequireProofKey(false);
        }
        clientMapper.insert(client);
        log.info("RegisteredClient created: tenantId={}, clientId={}, id={}",
                client.getTenantId(), client.getClientId(), client.getId());
        return client;
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "registeredClient", allEntries = true)
    public SysRegisteredClient updateClient(SysRegisteredClient client) {
        SysRegisteredClient existing = clientMapper.selectById(client.getId());
        if (existing == null) {
            throw new BusinessException("客户端不存在: " + client.getId());
        }
        // 不可修改 (tenantId, clientId)
        client.setTenantId(null);
        client.setClientId(null);
        clientMapper.updateById(client);
        log.info("RegisteredClient updated: id={}", client.getId());
        return clientMapper.selectById(client.getId());
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "registeredClient", allEntries = true)
    public void deleteClient(UUID id) {
        SysRegisteredClient client = clientMapper.selectById(id);
        if (client == null) {
            throw new BusinessException("客户端不存在: " + id);
        }
        clientMapper.deleteById(id);
        log.info("RegisteredClient deleted: id={}", id);
    }
}
