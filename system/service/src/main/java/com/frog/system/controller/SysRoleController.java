package com.frog.system.controller;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.frog.common.domain.PageResult;
import com.frog.common.log.annotation.AuditLog;
import com.frog.common.response.ApiResults;
import com.frog.common.dto.role.RoleDTO;
import com.frog.system.service.ISysRoleService;
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
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * 角色管理控制器
 *
 * @author Deng
 * createData 2025/10/14 18:01
 * @version 1.0
 */
@RestController
@RequestMapping("/v1/api/system/roles")
@RequiredArgsConstructor
@Tag(name = "角色模块", description = "系统角色管理相关接口，包括角色的增删改查、权限分配等功能")
public class SysRoleController {
    private final ISysRoleService roleService;

    /**
     * 查询角色列表
     */
    @GetMapping
    @PreAuthorize("hasAuthority('system:role:list')")
    @Operation(summary = "查询角色列表", description = "分页查询系统角色列表，支持角色名称模糊查询")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功",
                    content = @Content(schema = @Schema(implementation = PageResult.class))),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    public ApiResults<PageResult<RoleDTO>> list(
            @Parameter(description = "页码", example = "1") @RequestParam(defaultValue = "1") Integer page,
            @Parameter(description = "每页大小", example = "10") @RequestParam(defaultValue = "10") Integer size,
            @Parameter(description = "角色名称（模糊查询）") @RequestParam(required = false) String roleName) {
        Page<RoleDTO> result = roleService.listRoles(page, size, roleName);

        return ApiResults.success(PageResult.of(result));
    }

    /**
     * 查询所有角色（用于下拉选择）
     */
    @GetMapping("/all")
    @PreAuthorize("hasAuthority('system:role:list')")
    @Operation(summary = "查询所有角色", description = "获取所有角色列表，不分页，用于下拉选择框")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    public ApiResults<List<RoleDTO>> listAll() {
        List<RoleDTO> roles = roleService.listAllRoles();

        return ApiResults.success(roles);
    }

    /**
     * 新增角色
     */
    @PostMapping
    @PreAuthorize("hasAuthority('system:role:add')")
    @Operation(summary = "新增角色", description = "创建新的系统角色")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "创建成功"),
            @ApiResponse(responseCode = "400", description = "请求参数校验失败"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "新增角色",
            businessType = "ROLE",
            riskLevel = 4
    )
    public ApiResults<Void> add(
            @Parameter(description = "角色信息", required = true) @Validated @RequestBody RoleDTO roleDTO) {
        roleService.addRole(roleDTO);

        return ApiResults.success();
    }

    /**
     * 修改角色
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('system:role:edit')")
    @Operation(summary = "修改角色", description = "更新角色信息")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "更新成功"),
            @ApiResponse(responseCode = "400", description = "请求参数校验失败"),
            @ApiResponse(responseCode = "404", description = "角色不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "修改角色",
            businessType = "ROLE",
            riskLevel = 4
    )
    public ApiResults<Void> update(
            @Parameter(description = "角色 ID", required = true) @PathVariable UUID id,
            @Parameter(description = "角色信息", required = true) @Validated @RequestBody RoleDTO roleDTO) {
        roleDTO.setId(id);
        roleService.updateRole(roleDTO);

        return ApiResults.success();
    }

    /**
     * 删除角色
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('system:role:delete')")
    @Operation(summary = "删除角色", description = "删除指定角色（软删除）")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "删除成功"),
            @ApiResponse(responseCode = "404", description = "角色不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "删除角色",
            businessType = "ROLE",
            riskLevel = 4
    )
    public ApiResults<Void> delete(
            @Parameter(description = "角色 ID", required = true) @PathVariable UUID id) {
        roleService.deleteRole(id);

        return ApiResults.success();
    }

    /**
     * 授权权限
     */
    @PostMapping("/{id}/grant-permissions")
    @PreAuthorize("hasAuthority('system:role:edit')")
    @Operation(summary = "角色授权", description = "为角色分配权限")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "授权成功"),
            @ApiResponse(responseCode = "404", description = "角色或权限不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "角色授权",
            businessType = "ROLE",
            riskLevel = 4
    )
    public ApiResults<Void> grantPermissions(
            @Parameter(description = "角色 ID", required = true) @PathVariable UUID id,
            @Parameter(description = "权限 ID列表", required = true) @RequestBody List<UUID> permissionIds) {
        roleService.grantPermissions(id, permissionIds);

        return ApiResults.success();
    }

    /**
     * 查询角色权限
     */
    @GetMapping("/{id}/permissions")
    @PreAuthorize("hasAuthority('system:role:list')")
    @Operation(summary = "查询角色权限", description = "获取角色已分配的权限 ID列表")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功"),
            @ApiResponse(responseCode = "404", description = "角色不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    public ApiResults<List<UUID>> getRolePermissions(
            @Parameter(description = "角色 ID", required = true) @PathVariable UUID id) {
        List<UUID> permissionIds = roleService.getRolePermissionIds(id);

        return ApiResults.success(permissionIds);
    }
}

