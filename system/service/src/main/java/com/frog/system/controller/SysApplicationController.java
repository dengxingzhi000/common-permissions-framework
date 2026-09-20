package com.frog.system.controller;

import com.frog.common.log.annotation.AuditLog;
import com.frog.common.response.ApiResults;
import com.frog.system.domain.entity.SysApplication;
import com.frog.system.service.ISysApplicationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * 应用管理控制器 — Phase 1.1。
 *
 * <p>当前阶段仅做平台级管理,所有接口需要 {@code system:admin} 权限。
 * 后续阶段会引入 per-tenant 隔离(tenantId from TenantContext)。
 *
 * @author Deng
 * @since 2026-09-22
 */
@RestController
@RequestMapping("/v1/api/system/applications")
@RequiredArgsConstructor
@Tag(name = "应用模块", description = "系统应用管理(Phase 1.1)")
public class SysApplicationController {

    private final ISysApplicationService applicationService;

    /**
     * 查询租户下所有应用
     */
    @GetMapping
    @PreAuthorize("hasAuthority('system:admin')")
    @Operation(summary = "查询应用列表", description = "按 tenantId 查询该租户下的所有应用")
    public ApiResults<List<SysApplication>> listByTenant(
            @Parameter(description = "租户ID", required = true) @RequestParam UUID tenantId) {
        return ApiResults.success(applicationService.listByTenantId(tenantId));
    }

    /**
     * 查询应用详情
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('system:admin')")
    @Operation(summary = "查询应用详情")
    public ApiResults<SysApplication> getById(
            @Parameter(description = "应用ID") @PathVariable UUID id) {
        SysApplication app = applicationService.getById(id);
        if (app == null) {
            return ApiResults.success(null);
        }
        return ApiResults.success(app);
    }

    /**
     * 新增应用
     */
    @PostMapping
    @PreAuthorize("hasAuthority('system:admin')")
    @AuditLog(operation = "新增应用", businessType = "APPLICATION", riskLevel = 4)
    @Operation(summary = "新增应用")
    public ApiResults<SysApplication> add(
            @Parameter(description = "应用信息") @Validated @RequestBody SysApplication application) {
        return ApiResults.success(applicationService.addApplication(application));
    }

    /**
     * 修改应用
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('system:admin')")
    @AuditLog(operation = "修改应用", businessType = "APPLICATION", riskLevel = 3)
    @Operation(summary = "修改应用")
    public ApiResults<SysApplication> update(
            @Parameter(description = "应用ID") @PathVariable UUID id,
            @Parameter(description = "应用信息") @Validated @RequestBody SysApplication application) {
        application.setId(id);
        return ApiResults.success(applicationService.updateApplication(application));
    }

    /**
     * 删除应用(软删除)
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('system:admin')")
    @AuditLog(operation = "删除应用", businessType = "APPLICATION", riskLevel = 4)
    @Operation(summary = "删除应用")
    public ApiResults<Void> delete(
            @Parameter(description = "应用ID") @PathVariable UUID id) {
        applicationService.deleteApplication(id);
        return ApiResults.success();
    }

    /**
     * Used by swagger annotation
     */
    @ApiResponses({})
    @SuppressWarnings("unused")
    private void unused() {
        // empty placeholder to ensure @ApiResponses is on import list
    }
}
