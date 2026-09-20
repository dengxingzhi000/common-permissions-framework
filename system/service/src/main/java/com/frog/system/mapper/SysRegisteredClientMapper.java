package com.frog.system.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.frog.system.domain.entity.SysRegisteredClient;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.Optional;
import java.util.UUID;

/**
 * OAuth2 注册客户端 Mapper — sys_registered_client。
 *
 * @author Deng
 * @since 2026-09-23
 */
@Mapper
public interface SysRegisteredClientMapper extends BaseMapper<SysRegisteredClient> {

    /**
     * 根据 client_id 查询(全局唯一索引,不含 tenant 过滤)。
     *
     * <p>注意:OAuth2 client_id 必须在所有租户间唯一,因此这里不做 tenant 过滤。
     * Spring Authorization Server 的 {@code RegisteredClientRepository.findByClientId}
     * 调用方期望单条结果。
     */
    @Select("""
            SELECT * FROM sys_registered_client
            WHERE client_id = #{clientId} AND NOT deleted
            """)
    SysRegisteredClient findByClientId(@Param("clientId") String clientId);

    /**
     * {@link #findByClientId} 的 Optional 包装。
     */
    default Optional<SysRegisteredClient> findOptionalByClientId(String clientId) {
        return Optional.ofNullable(findByClientId(clientId));
    }

    /**
     * 根据租户 ID + client_id 查询。
     *
     * <p>用于 tenant-scoped 接口(如 admin UI)。
     */
    @Select("""
            SELECT * FROM sys_registered_client
            WHERE tenant_id = #{tenantId} AND client_id = #{clientId} AND NOT deleted
            """)
    SysRegisteredClient findByTenantAndClientId(@Param("tenantId") UUID tenantId,
                                                @Param("clientId") String clientId);
}
