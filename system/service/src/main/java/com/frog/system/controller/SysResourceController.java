package com.frog.system.controller;

import com.frog.common.log.annotation.AuditLog;
import com.frog.common.response.ApiResults;
import com.frog.system.domain.entity.SysResource;
import com.frog.system.service.ISysResourceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
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
 * 资源目录管理控制器 — Phase 1.7。
 *
 * <p>所有接口要求 {@code system:admin} 权限。提供类型化资源目录的查询、新增、
 * 修改、删除,以及按 (租户, 应用, 类型) 过滤查询。
 *
 * @author Deng
 * @since 2026-09-24
 */
@RestController
@RequestMapping("/v1/api/system/resources")
@RequiredArgsConstructor
@Tag(name = "资源目录", description = "类型化资源目录管理(Phase 1.7)")
public class SysResourceController {

    private final ISysResourceService resourceService;

    @GetMapping
    @PreAuthorize("hasAuthority('system:admin')")
    @Operation(summary = "查询资源列表", description = "按 (tenantId, appId) 查询资源")
    public ApiResults<List<SysResource>> list(
            @Parameter(description = "租户ID", required = true) @RequestParam UUID tenantId,
            @Parameter(description = "应用ID", required = true) @RequestParam UUID appId) {
        return ApiResults.success(resourceService.listByTenantAndApp(tenantId, appId));
    }

    @GetMapping("/by-type")
    @PreAuthorize("hasAuthority('system:admin')")
    @Operation(summary = "按资源类型查询")
    public ApiResults<List<SysResource>> listByType(
            @Parameter(description = "租户ID", required = true) @RequestParam UUID tenantId,
            @Parameter(description = "应用ID", required = true) @RequestParam UUID appId,
            @Parameter(description = "资源类型", required = true) @RequestParam String resourceType) {
        return ApiResults.success(
                resourceService.listByTenantAppType(tenantId, appId, resourceType));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('system:admin')")
    @Operation(summary = "查询资源详情")
    public ApiResults<SysResource> getById(
            @Parameter(description = "资源ID") @PathVariable UUID id) {
        SysResource resource = resourceService.getById(id);
        return ApiResults.success(resource);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('system:admin')")
    @AuditLog(operation = "新增资源", businessType = "RESOURCE", riskLevel = 3)
    @Operation(summary = "新增资源")
    public ApiResults<SysResource> add(
            @Parameter(description = "资源信息") @Validated @RequestBody SysResource resource) {
        return ApiResults.success(resourceService.addResource(resource));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('system:admin')")
    @AuditLog(operation = "修改资源", businessType = "RESOURCE", riskLevel = 2)
    @Operation(summary = "修改资源")
    public ApiResults<SysResource> update(
            @Parameter(description = "资源ID") @PathVariable UUID id,
            @Parameter(description = "资源信息") @Validated @RequestBody SysResource resource) {
        resource.setId(id);
        return ApiResults.success(resourceService.updateResource(resource));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('system:admin')")
    @AuditLog(operation = "删除资源", businessType = "RESOURCE", riskLevel = 3)
    @Operation(summary = "删除资源(软删除)")
    public ApiResults<Void> delete(
            @Parameter(description = "资源ID") @PathVariable UUID id) {
        resourceService.deleteResource(id);
        return ApiResults.success();
    }
}