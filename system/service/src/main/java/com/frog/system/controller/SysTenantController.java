package com.frog.system.controller;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.frog.common.domain.PageResult;
import com.frog.common.log.annotation.AuditLog;
import com.frog.common.response.ApiResults;
import com.frog.system.domain.entity.SysTenant;
import com.frog.system.service.ISysTenantService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
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

import java.util.UUID;

/**
 * 租户管理控制器 — Phase 1.1。
 *
 * <p>当前阶段仅做平台级管理(不做租户范围隔离),所有接口需要 {@code system:admin} 权限。
 *
 * @author Deng
 * @since 2026-09-22
 */
@RestController
@RequestMapping("/v1/api/system/tenants")
@RequiredArgsConstructor
@Tag(name = "租户模块", description = "系统租户管理(Phase 1.1)")
public class SysTenantController {

    private final ISysTenantService tenantService;

    /**
     * 分页查询租户列表
     */
    @GetMapping
    @PreAuthorize("hasAuthority('system:admin')")
    @Operation(summary = "查询租户列表", description = "分页查询系统租户列表")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功",
                    content = @Content(schema = @Schema(implementation = PageResult.class))),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    public ApiResults<PageResult<SysTenant>> list(
            @Parameter(description = "页码", example = "1") @RequestParam(defaultValue = "1") Integer page,
            @Parameter(description = "每页大小", example = "10") @RequestParam(defaultValue = "10") Integer size,
            @Parameter(description = "租户编码(模糊查询)") @RequestParam(required = false) String tenantCode,
            @Parameter(description = "状态") @RequestParam(required = false) Integer status) {
        Page<SysTenant> result = tenantService.listTenants(page, size, tenantCode, status);
        return ApiResults.success(PageResult.of(result));
    }

    /**
     * 查询租户详情
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('system:admin')")
    @Operation(summary = "查询租户详情")
    public ApiResults<SysTenant> getById(
            @Parameter(description = "租户ID") @PathVariable UUID id) {
        SysTenant tenant = tenantService.getById(id);
        if (tenant == null) {
            return ApiResults.success(null);
        }
        return ApiResults.success(tenant);
    }

    /**
     * 根据 tenantCode 查询
     */
    @GetMapping("/by-code/{tenantCode}")
    @PreAuthorize("hasAuthority('system:admin')")
    @Operation(summary = "根据编码查询租户")
    public ApiResults<SysTenant> getByCode(
            @Parameter(description = "租户编码") @PathVariable String tenantCode) {
        return ApiResults.success(tenantService.getByTenantCode(tenantCode));
    }

    /**
     * 新增租户
     */
    @PostMapping
    @PreAuthorize("hasAuthority('system:admin')")
    @AuditLog(operation = "新增租户", businessType = "TENANT", riskLevel = 4)
    @Operation(summary = "新增租户")
    public ApiResults<SysTenant> add(
            @Parameter(description = "租户信息") @Validated @RequestBody SysTenant tenant) {
        SysTenant created = tenantService.addTenant(tenant);
        return ApiResults.success(created);
    }

    /**
     * 修改租户
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('system:admin')")
    @AuditLog(operation = "修改租户", businessType = "TENANT", riskLevel = 3)
    @Operation(summary = "修改租户")
    public ApiResults<SysTenant> update(
            @Parameter(description = "租户ID") @PathVariable UUID id,
            @Parameter(description = "租户信息") @Validated @RequestBody SysTenant tenant) {
        tenant.setId(id);
        return ApiResults.success(tenantService.updateTenant(tenant));
    }

    /**
     * 启用租户
     */
    @PostMapping("/{id}/enable")
    @PreAuthorize("hasAuthority('system:admin')")
    @AuditLog(operation = "启用租户", businessType = "TENANT", riskLevel = 3)
    @Operation(summary = "启用租户")
    public ApiResults<Void> enable(
            @Parameter(description = "租户ID") @PathVariable UUID id) {
        tenantService.enableTenant(id);
        return ApiResults.success();
    }

    /**
     * 禁用租户
     */
    @PostMapping("/{id}/disable")
    @PreAuthorize("hasAuthority('system:admin')")
    @AuditLog(operation = "禁用租户", businessType = "TENANT", riskLevel = 4)
    @Operation(summary = "禁用租户")
    public ApiResults<Void> disable(
            @Parameter(description = "租户ID") @PathVariable UUID id) {
        tenantService.disableTenant(id);
        return ApiResults.success();
    }

    /**
     * 删除租户(软删除)
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('system:admin')")
    @AuditLog(operation = "删除租户", businessType = "TENANT", riskLevel = 4)
    @Operation(summary = "删除租户")
    public ApiResults<Void> delete(
            @Parameter(description = "租户ID") @PathVariable UUID id) {
        tenantService.deleteTenant(id);
        return ApiResults.success();
    }
}
