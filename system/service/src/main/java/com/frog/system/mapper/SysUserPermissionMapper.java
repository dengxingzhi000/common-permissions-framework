package com.frog.system.mapper;

import com.baomidou.dynamic.datasource.annotation.DS;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.frog.system.domain.entity.SysUserPermission;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.Set;
import java.util.UUID;

@Mapper
@DS("permission")
public interface SysUserPermissionMapper extends BaseMapper<SysUserPermission> {

    /**
     * 查询用户在有效期内直接授予的权限编码集合。
     * 永久授予(effective/expire_time 都为 NULL)始终生效。
     */
    @Select("""
            SELECT p.permission_code
            FROM sys_user_permission up
            JOIN sys_permission p ON p.id = up.permission_id AND p.deleted = FALSE
            WHERE up.user_id = #{userId}
              AND p.status = 1
              AND (up.effective_time IS NULL OR up.effective_time <= NOW())
              AND (up.expire_time IS NULL OR up.expire_time > NOW())
            """)
    Set<String> findPermissionCodesByUserId(@Param("userId") UUID userId);
}
