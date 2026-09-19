package com.frog.common.config;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface SysConfigMapper {

    @Select("""
        SELECT id, config_key, config_value, scope, tenant_id, description,
               status, create_time, update_time
        FROM sys_config
        WHERE config_key = #{key}
          AND (tenant_id = #{tenantId} OR (scope = 'GLOBAL' AND tenant_id IS NULL))
        ORDER BY (tenant_id IS NOT NULL) DESC
        LIMIT 1
        """)
    SysConfig selectByKey(@Param("key") String key,
                           @Param("tenantId") String tenantId);
}