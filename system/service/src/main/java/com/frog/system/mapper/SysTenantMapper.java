package com.frog.system.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.frog.system.domain.entity.SysTenant;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.Optional;
import java.util.UUID;

/**
 * 租户 Mapper — sys_tenant。
 *
 * <p>注意:此表不依赖特定数据源(默认数据源)。租户是平台级元数据,
 * 不挂在 db_user / db_permission 等任何业务库上。
 *
 * @author Deng
 * @since 2026-09-22
 */
@Mapper
public interface SysTenantMapper extends BaseMapper<SysTenant> {

    /**
     * 根据 tenantCode 查询
     */
    @Select("""
            SELECT * FROM sys_tenant
            WHERE tenant_code = #{tenantCode} AND NOT deleted
            """)
    SysTenant findByTenantCode(@Param("tenantCode") String tenantCode);

    /**
     * 根据 tenantCode 查询(Optional)
     */
    default Optional<SysTenant> findOptionalByTenantCode(String tenantCode) {
        return Optional.ofNullable(findByTenantCode(tenantCode));
    }

    /**
     * 检查 tenantCode 是否已存在
     */
    @Select("""
            SELECT COUNT(*) > 0 FROM sys_tenant
            WHERE tenant_code = #{tenantCode} AND NOT deleted
            """)
    boolean existsByTenantCode(@Param("tenantCode") String tenantCode);
}
