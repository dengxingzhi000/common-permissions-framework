package com.frog.system.controller;

import com.frog.common.log.annotation.AuditLog;
import com.frog.common.dto.permission.ApiPermissionDTO;
import com.frog.common.dto.permission.PermissionDTO;
import com.frog.common.response.ApiResults;
import com.frog.system.service.ISysPermissionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * 权限管理控制器
 *
 * @author Deng
 * createData 2025/10/14 17:47
 * @version 1.0
 */
@RestController
@RequestMapping("/api/system/permissions")
@RequiredArgsConstructor
@Tag(name = "权限模块", description = "系统权限管理相关接口，包括权限的增删改查、权限树查询、API权限映射等功能")
public class SysPermissionController {
    private final ISysPermissionService permissionService;

    /**
     * 查询权限树
     */
    @GetMapping("/tree")
    @PreAuthorize("hasAuthority('system:permission:list')")
    @Operation(summary = "查询权限树", description = "获取系统权限树形结构，包含所有权限的层级关系")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    public ApiResults<List<PermissionDTO>> tree() {
        List<PermissionDTO> tree = permissionService.getPermissionTree();

        return ApiResults.success(tree);
    }

    /**
     * 新增权限
     */
    @PostMapping
    @PreAuthorize("hasAuthority('system:permission:add')")
    @Operation(summary = "新增权限", description = "创建新的系统权限")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "创建成功"),
            @ApiResponse(responseCode = "400", description = "请求参数校验失败"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "新增权限",
            businessType = "PERMISSION",
            riskLevel = 4
    )
    public ApiResults<Void> add(
            @Parameter(description = "权限信息", required = true) @Validated @RequestBody PermissionDTO permissionDTO) {
        permissionService.addPermission(permissionDTO);

        return ApiResults.success();
    }

    /**
     * 修改权限
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('system:permission:edit')")
    @Operation(summary = "修改权限", description = "更新权限信息")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "更新成功"),
            @ApiResponse(responseCode = "400", description = "请求参数校验失败"),
            @ApiResponse(responseCode = "404", description = "权限不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "修改权限",
            businessType = "PERMISSION",
            riskLevel = 4
    )
    public ApiResults<Void> update(
            @Parameter(description = "权限 ID", required = true) @PathVariable UUID id,
            @Parameter(description = "权限信息", required = true) @Validated @RequestBody PermissionDTO permissionDTO) {
        permissionDTO.setId(id);
        permissionService.updatePermission(permissionDTO);

        return ApiResults.success();
    }

    /**
     * 删除权限
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('system:permission:delete')")
    @Operation(summary = "删除权限", description = "删除指定权限（软删除）")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "删除成功"),
            @ApiResponse(responseCode = "404", description = "权限不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "删除权限",
            businessType = "PERMISSION",
            riskLevel = 4
    )
    public ApiResults<Void> delete(
            @Parameter(description = "权限 ID", required = true) @PathVariable UUID id) {
        permissionService.deletePermission(id);

        return ApiResults.success();
    }

    /**
     * 根据 id查询权限
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('system:permission:list')")
    @Operation(summary = "查询权限详情", description = "根据权限 ID查询权限详细信息")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功"),
            @ApiResponse(responseCode = "404", description = "权限不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    public ApiResults<PermissionDTO> getById(
            @Parameter(description = "权限 ID", required = true) @PathVariable UUID id) {
        PermissionDTO permissionDTO = permissionService.getPermissionById(id);

        return ApiResults.success(permissionDTO);
    }

    /**
     * 查询用户权限（用于 Feign 调用）
     * 对应 Dubbo: PermissionDubboService.findAllPermissionsByUserId
     */
    @GetMapping("/user/{userId}")
    @Operation(summary = "查询用户权限", description = "获取用户拥有的所有权限标识符集合（用于Feign调用）")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功"),
            @ApiResponse(responseCode = "404", description = "用户不存在")
    })
    public ApiResults<Set<String>> getUserPermissions(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID userId) {
        Set<String> permissions = permissionService.getUserPermissions(userId);

        return ApiResults.success(permissions);
    }

    /**
     * 根据 URL 和 HTTP 方法查询权限（用于 Feign 调用）
     * 对应 Dubbo: PermissionDubboService.findPermissionsByUrl
     */
    @GetMapping("/find-by-url")
    @PreAuthorize("hasAnyAuthority('system:permission:query', 'system:admin')")
    @Operation(summary = "根据 URL查询权限", description = "根据API路径和HTTP方法查询所需权限标识符（用于动态权限校验）")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    public List<String> findPermissionsByUrl(
            @Parameter(description = "API 路径", required = true, example = "/api/system/users") @RequestParam("url") String url,
            @Parameter(description = "HTTP 方法", required = true, example = "GET") @RequestParam("method") String method) {
        return permissionService.findPermissionsByUrl(url, method);
    }

    /**
     * 查询所有 API 权限（用于动态权限加载）
     * 用于 DynamicPermissionLoader 加载权限映射
     */
    @GetMapping("/api")
    @Operation(summary = "查询所有 API权限", description = "获取所有API权限映射，用于动态权限加载器初始化")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功")
    })
    public List<ApiPermissionDTO> findApiPermissions() {
        return permissionService.findApiPermissions();
    }
}
