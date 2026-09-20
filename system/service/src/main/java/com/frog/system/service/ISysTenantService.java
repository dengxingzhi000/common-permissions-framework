package com.frog.system.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.IService;
import com.frog.system.domain.entity.SysTenant;

import java.util.UUID;

/**
 * 租户服务 — sys_tenant。
 *
 * @author Deng
 * @since 2026-09-22
 */
public interface ISysTenantService extends IService<SysTenant> {

    /**
     * 分页查询租户列表
     *
     * @param pageNum    页码
     * @param pageSize   每页大小
     * @param tenantCode 租户编码(可选,模糊匹配)
     * @param status     状态(可选)
     */
    Page<SysTenant> listTenants(Integer pageNum, Integer pageSize,
                                String tenantCode, Integer status);

    /**
     * 根据 tenantCode 获取租户
     */
    SysTenant getByTenantCode(String tenantCode);

    /**
     * 新增租户
     */
    SysTenant addTenant(SysTenant tenant);

    /**
     * 修改租户
     */
    SysTenant updateTenant(SysTenant tenant);

    /**
     * 禁用租户(status=0)
     */
    void disableTenant(UUID id);

    /**
     * 启用租户(status=1)
     */
    void enableTenant(UUID id);

    /**
     * 软删除租户
     */
    void deleteTenant(UUID id);
}
