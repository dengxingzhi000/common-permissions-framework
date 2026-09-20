package com.frog.system.service.Impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.frog.common.exception.BusinessException;
import com.frog.common.security.oauth2.SysRegisteredClientDTO;
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
 * <p>对外契约使用 {@link SysRegisteredClientDTO}(位于
 * {@code common/security-api});持久化与映射在服务内部完成,
 * 维持 {@code common/*} 不依赖 {@code system/service}。
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
    public Optional<SysRegisteredClientDTO> findOptionalByClientId(String clientId) {
        return clientMapper.findOptionalByClientId(clientId).map(this::toDto);
    }

    @Override
    public SysRegisteredClientDTO findByClientId(String clientId) {
        SysRegisteredClient entity = clientMapper.findByClientId(clientId);
        return entity == null ? null : toDto(entity);
    }

    @Override
    public SysRegisteredClientDTO findByTenantAndClientId(UUID tenantId, String clientId) {
        SysRegisteredClient entity = clientMapper.findByTenantAndClientId(tenantId, clientId);
        return entity == null ? null : toDto(entity);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "registeredClient", allEntries = true)
    public SysRegisteredClientDTO addClient(SysRegisteredClientDTO client) {
        if (client.getTenantId() == null) {
            throw new BusinessException("租户ID不能为空");
        }
        if (client.getClientId() == null || client.getClientId().isBlank()) {
            throw new BusinessException("client_id 不能为空");
        }
        if (clientMapper.findByClientId(client.getClientId()) != null) {
            throw new BusinessException("client_id 已存在(全局唯一): " + client.getClientId());
        }

        SysRegisteredClient entity = toEntity(client);
        if (entity.getId() == null) {
            entity.setId(UUIDv7Util.generate());
        }
        if (entity.getStatus() == null) {
            entity.setStatus(1);
        }
        if (entity.getAccessTokenTtlSeconds() == null) {
            entity.setAccessTokenTtlSeconds(7200);
        }
        if (entity.getRefreshTokenTtlSeconds() == null) {
            entity.setRefreshTokenTtlSeconds(604800);
        }
        if (entity.getRequireAuthorizationConsent() == null) {
            entity.setRequireAuthorizationConsent(false);
        }
        if (entity.getRequireProofKey() == null) {
            entity.setRequireProofKey(false);
        }
        clientMapper.insert(entity);
        log.info("RegisteredClient created: tenantId={}, clientId={}, id={}",
                entity.getTenantId(), entity.getClientId(), entity.getId());
        return toDto(entity);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "registeredClient", allEntries = true)
    public SysRegisteredClientDTO updateClient(SysRegisteredClientDTO client) {
        SysRegisteredClient existing = clientMapper.selectById(client.getId());
        if (existing == null) {
            throw new BusinessException("客户端不存在: " + client.getId());
        }
        // 不可修改 (tenantId, clientId)
        existing.setClientSecretHash(client.getClientSecretHash());
        existing.setClientAuthMethods(client.getClientAuthMethods());
        existing.setGrantTypes(client.getGrantTypes());
        existing.setRedirectUris(client.getRedirectUris());
        existing.setPostLogoutRedirectUris(client.getPostLogoutRedirectUris());
        existing.setScopes(client.getScopes());
        existing.setRequireAuthorizationConsent(client.getRequireAuthorizationConsent());
        existing.setRequireProofKey(client.getRequireProofKey());
        existing.setAccessTokenTtlSeconds(client.getAccessTokenTtlSeconds());
        existing.setRefreshTokenTtlSeconds(client.getRefreshTokenTtlSeconds());
        existing.setStatus(client.getStatus());
        clientMapper.updateById(existing);
        log.info("RegisteredClient updated: id={}", existing.getId());
        SysRegisteredClient reloaded = clientMapper.selectById(existing.getId());
        return reloaded == null ? null : toDto(reloaded);
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

    /**
     * 实体 → DTO。{@code audit} / {@code deleted} 不暴露给 API 表面。
     */
    private SysRegisteredClientDTO toDto(SysRegisteredClient entity) {
        if (entity == null) {
            return null;
        }
        return SysRegisteredClientDTO.builder()
                .id(entity.getId())
                .tenantId(entity.getTenantId())
                .applicationId(entity.getApplicationId())
                .clientId(entity.getClientId())
                .clientSecretHash(entity.getClientSecretHash())
                .clientAuthMethods(entity.getClientAuthMethods())
                .grantTypes(entity.getGrantTypes())
                .redirectUris(entity.getRedirectUris())
                .postLogoutRedirectUris(entity.getPostLogoutRedirectUris())
                .scopes(entity.getScopes())
                .requireAuthorizationConsent(entity.getRequireAuthorizationConsent())
                .requireProofKey(entity.getRequireProofKey())
                .accessTokenTtlSeconds(entity.getAccessTokenTtlSeconds())
                .refreshTokenTtlSeconds(entity.getRefreshTokenTtlSeconds())
                .status(entity.getStatus())
                .createTime(entity.getCreateTime())
                .updateTime(entity.getUpdateTime())
                .build();
    }

    /**
     * DTO → 实体(仅写入路径使用)。{@code audit} 初始为 null,
     * {@code createTime}/{@code updateTime} 由 MyBatis-Plus 字段填充策略写入。
     */
    private SysRegisteredClient toEntity(SysRegisteredClientDTO dto) {
        if (dto == null) {
            return null;
        }
        SysRegisteredClient entity = new SysRegisteredClient();
        entity.setId(dto.getId());
        entity.setTenantId(dto.getTenantId());
        entity.setApplicationId(dto.getApplicationId());
        entity.setClientId(dto.getClientId());
        entity.setClientSecretHash(dto.getClientSecretHash());
        entity.setClientAuthMethods(dto.getClientAuthMethods());
        entity.setGrantTypes(dto.getGrantTypes());
        entity.setRedirectUris(dto.getRedirectUris());
        entity.setPostLogoutRedirectUris(dto.getPostLogoutRedirectUris());
        entity.setScopes(dto.getScopes());
        entity.setRequireAuthorizationConsent(dto.getRequireAuthorizationConsent());
        entity.setRequireProofKey(dto.getRequireProofKey());
        entity.setAccessTokenTtlSeconds(dto.getAccessTokenTtlSeconds());
        entity.setRefreshTokenTtlSeconds(dto.getRefreshTokenTtlSeconds());
        entity.setStatus(dto.getStatus());
        return entity;
    }
}
