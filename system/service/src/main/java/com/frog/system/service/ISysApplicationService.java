package com.frog.system.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.frog.system.domain.entity.SysApplication;

import java.util.List;
import java.util.UUID;

/**
 * 应用服务 — sys_application。
 *
 * @author Deng
 * @since 2026-09-22
 */
public interface ISysApplicationService extends IService<SysApplication> {

    /**
     * 查询租户下所有应用
     */
    List<SysApplication> listByTenantId(UUID tenantId);

    /**
     * 根据 (tenantId, appCode) 获取应用
     */
    SysApplication getByTenantAndCode(UUID tenantId, String appCode);

    /**
     * 新增应用
     */
    SysApplication addApplication(SysApplication application);

    /**
     * 修改应用
     */
    SysApplication updateApplication(SysApplication application);

    /**
     * 软删除应用
     */
    void deleteApplication(UUID id);
}
