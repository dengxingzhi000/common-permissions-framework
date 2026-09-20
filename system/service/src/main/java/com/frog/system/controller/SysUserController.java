package com.frog.system.controller;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.frog.common.feign.client.SysAuthServiceClient;
import com.frog.common.log.annotation.AuditLog;
import com.frog.common.domain.PageResult;
import com.frog.common.dto.user.ChangePasswordRequest;
import com.frog.common.dto.role.TemporaryRoleGrantDTO;
import com.frog.common.dto.user.UserDTO;
import com.frog.common.response.ApiResults;
import com.frog.common.web.util.SecurityUtils;
import com.frog.system.service.ISysPermissionService;
import com.frog.system.service.ISysUserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 用户管理控制器
 *
 * @author Deng
 * createData 2025/10/14 18:00
 * @version 1.0
 */
@RestController
@RequestMapping("/v1/api/system/users")
@RequiredArgsConstructor
@Tag(name = "用户模块", description = "系统用户管理相关接口，包括用户的增删改查、角色授权、密码管理等功能")
public class SysUserController {
    private final ISysUserService userService;
    private final ISysPermissionService permissionService;
    private final SysAuthServiceClient authServiceClient;

    /**
     * 查询用户列表
     */
    @GetMapping
    @PreAuthorize("hasAuthority('system:user:list')")
    @Operation(summary = "查询用户列表", description = "分页查询系统用户列表，支持用户名和状态过滤")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功",
                    content = @Content(schema = @Schema(implementation = PageResult.class))),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    public ApiResults<PageResult<UserDTO>> list(
            @Parameter(description = "页码", example = "1") @RequestParam(defaultValue = "1") Integer page,
            @Parameter(description = "每页大小", example = "10") @RequestParam(defaultValue = "10") Integer size,
            @Parameter(description = "用户名（模糊查询）") @RequestParam(required = false) String username,
            @Parameter(description = "用户状态（0:禁用 1:启用）") @RequestParam(required = false) Integer status) {
        Page<UserDTO> result = userService.listUsers(page, size, username, status);

        return ApiResults.success(PageResult.of(result));
    }

    /**
     * 查询用户详情
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('system:user:list')")
    @Operation(summary = "查询用户详情", description = "根据用户 ID查询用户详细信息")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功"),
            @ApiResponse(responseCode = "404", description = "用户不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    public ApiResults<UserDTO> getById(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID id) {
        UserDTO user = userService.getUserById(id);

        return ApiResults.success(user);
    }

    /**
     * 新增用户
     */
    @PostMapping
    @PreAuthorize("hasAuthority('system:user:add')")
    @Operation(summary = "新增用户", description = "创建新的系统用户")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "创建成功"),
            @ApiResponse(responseCode = "400", description = "请求参数校验失败"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "新增用户",
            businessType = "USER"
    )
    public ApiResults<Void> add(
            @Parameter(description = "用户信息", required = true) @Validated @RequestBody UserDTO userDTO) {
        userService.addUser(userDTO);

        return ApiResults.success();
    }

    /**
     * 修改用户
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('system:user:edit')")
    @Operation(summary = "修改用户", description = "更新用户信息")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "更新成功"),
            @ApiResponse(responseCode = "400", description = "请求参数校验失败"),
            @ApiResponse(responseCode = "404", description = "用户不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "修改用户",
            businessType = "USER"
    )
    public ApiResults<Void> update(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID id,
            @Parameter(description = "用户信息", required = true) @Validated @RequestBody UserDTO userDTO) {
        userDTO.setId(id);
        userService.updateUser(userDTO);

        return ApiResults.success();
    }

    /**
     * 删除用户
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('system:user:delete')")
    @Operation(summary = "删除用户", description = "删除指定用户（软删除）")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "删除成功"),
            @ApiResponse(responseCode = "404", description = "用户不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "删除用户",
            businessType = "USER",
            riskLevel = 4
    )
    public ApiResults<Void> delete(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID id) {
        userService.deleteUser(id);

        return ApiResults.success();
    }

    /**
     * 修改密码
     */
    @PostMapping("/change-password")
    @Operation(summary = "修改密码", description = "用户修改自己的密码")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "修改成功"),
            @ApiResponse(responseCode = "400", description = "旧密码错误或新密码不符合规则")
    })
    public ApiResults<Void> changePassword(
            @Parameter(description = "修改密码请求", required = true) @Validated @RequestBody ChangePasswordRequest request) {
        UUID userId = SecurityUtils.getCurrentUserUuid().orElse(null);
        userService.changePassword(userId, request.getOldPassword(), request.getNewPassword());

        return ApiResults.success();
    }

    /**
     * 重置密码
     */
    @PostMapping("/{id}/reset-password")
    @PreAuthorize("hasAuthority('system:user:reset')")
    @Operation(summary = "重置密码", description = "管理员重置用户密码为默认密码")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "重置成功，返回新密码"),
            @ApiResponse(responseCode = "404", description = "用户不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "重置密码",
            businessType = "USER",
            riskLevel = 3
    )
    public ApiResults<String> resetPassword(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID id) {
        String newPassword = userService.resetPassword(id);

        return ApiResults.success(newPassword);
    }

    /**
     * 授权角色
     */
    @PostMapping("/{id}/grant-roles")
    @PreAuthorize("hasAuthority('system:user:grant')")
    @Operation(summary = "授权角色", description = "为用户分配角色")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "授权成功"),
            @ApiResponse(responseCode = "404", description = "用户或角色不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "授权角色",
            businessType = "USER",
            riskLevel = 4
    )
    public ApiResults<Void> grantRoles(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID id,
            @Parameter(description = "角色 ID列表", required = true) @RequestBody List<UUID> roleIds) {
        userService.grantRoles(id, roleIds);

        return ApiResults.success();
    }

    /**
     * 锁定/解锁用户
     */
    @PostMapping("/{id}/lock")
    @PreAuthorize("hasAuthority('system:user:edit')")
    @Operation(summary = "锁定/解锁用户", description = "锁定或解锁指定用户账号")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "操作成功"),
            @ApiResponse(responseCode = "404", description = "用户不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "锁定用户",
            businessType = "USER",
            riskLevel = 3
    )
    public ApiResults<Void> lockUser(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID id,
            @Parameter(description = "是否锁定（true:锁定 false:解锁）", required = true) @RequestParam Boolean lock) {
        userService.lockUser(id, lock);

        return ApiResults.success();
    }

    /**
     * 强制用户下线
     */
    @PostMapping("/{id}/force-logout")
    @PreAuthorize("hasAuthority('system:user:edit')")
    @Operation(summary = "强制用户下线", description = "强制指定用户退出登录")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "操作成功"),
            @ApiResponse(responseCode = "404", description = "用户不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "强制下线",
            businessType = "USER",
            riskLevel = 3
    )
    public ApiResults<Void> forceLogout(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID id,
            @Parameter(description = "强制下线原因", required = true) @RequestParam String reason) {
        authServiceClient.forceLogout(id, reason);

        return ApiResults.success();
    }

    /**
     * 授予临时角色
     */
    @PostMapping("/{id}/grant-temporary-roles")
    @PreAuthorize("hasAuthority('system:user:grant')")
    @Operation(summary = "授予临时角色", description = "为用户分配临时角色，支持设置生效和过期时间")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "授予成功"),
            @ApiResponse(responseCode = "400", description = "请求参数校验失败"),
            @ApiResponse(responseCode = "404", description = "用户或角色不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "授予临时角色",
            businessType = "USER",
            riskLevel = 4
    )
    public ApiResults<String> grantTemporaryRoles(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID id,
            @Parameter(description = "临时角色授权信息", required = true) @RequestBody @Validated TemporaryRoleGrantDTO dto) {
        userService.grantTemporaryRoles(
                id,
                dto.getRoleIds(),
                dto.getEffectiveTime(),
                dto.getExpireTime()
        );

        return ApiResults.success("临时角色授予成功");
    }

    /**
     * 延长临时角色有效期
     */
    @PostMapping("/{userId}/extend-temporary-role/{roleId}")
    @PreAuthorize("hasAuthority('system:user:grant')")
    @Operation(summary = "延长临时角色有效期", description = "延长用户临时角色的过期时间")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "延长成功"),
            @ApiResponse(responseCode = "404", description = "用户、角色或临时角色分配不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "延长临时角色",
            businessType = "USER",
            riskLevel = 3
    )
    public ApiResults<String> extendTemporaryRole(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID userId,
            @Parameter(description = "角色 ID", required = true) @PathVariable UUID roleId,
            @Parameter(description = "新的过期时间", required = true, example = "2025-12-31 23:59:59")
            @RequestParam @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss") LocalDateTime newExpireTime) {
        userService.extendTemporaryRole(userId, roleId, newExpireTime);

        return ApiResults.success("临时角色有效期已延长");
    }

    /**
     * 终止临时角色
     */
    @PostMapping("/{userId}/terminate-temporary-role/{roleId}")
    @PreAuthorize("hasAuthority('system:user:grant')")
    @Operation(summary = "终止临时角色", description = "立即终止用户的临时角色")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "终止成功"),
            @ApiResponse(responseCode = "404", description = "用户、角色或临时角色分配不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "终止临时角色",
            businessType = "USER",
            riskLevel = 3
    )
    public ApiResults<String> terminateTemporaryRole(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID userId,
            @Parameter(description = "角色 ID", required = true) @PathVariable UUID roleId) {
        userService.terminateTemporaryRole(userId, roleId);

        return ApiResults.success("临时角色已终止");
    }

    /**
     * 查询用户的临时角色列表
     */
    @GetMapping("/{id}/temporary-roles")
    @PreAuthorize("hasAuthority('system:user:list')")
    @Operation(summary = "查询用户的临时角色", description = "获取用户所有临时角色及其有效期信息")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功"),
            @ApiResponse(responseCode = "404", description = "用户不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    public ApiResults<List<Map<String, Object>>> getUserTemporaryRoles(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID id) {
        List<Map<String, Object>> roles = userService.getUserTemporaryRoles(id);

        return ApiResults.success(roles);
    }

    /**
     * 查询用户统计信息
     */
    @GetMapping("/{id}/statistics")
    @PreAuthorize("hasAuthority('system:user:list')")
    @Operation(summary = "查询用户统计信息", description = "获取用户的统计数据，如登录次数、最后登录时间等")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功"),
            @ApiResponse(responseCode = "404", description = "用户不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    public ApiResults<Map<String, Object>> getUserStatistics(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID id) {
        Map<String, Object> stats = userService.getUserStatistics(id);

        return ApiResults.success(stats);
    }

    /**
     * 更新最后登录信息
     */
    @GetMapping("/{userId}/update-login")
    @Operation(summary = "更新最后登录信息", description = "记录用户最后登录时间和 IP地址")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "更新成功"),
            @ApiResponse(responseCode = "404", description = "用户不存在")
    })
    public ApiResults<Void> updateLastLogin(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID userId,
            @Parameter(description = "登录 IP地址", required = true) @RequestParam("ipAddress") String ipAddress) {
        userService.updateLastLogin(userId, ipAddress);

        return ApiResults.success();
    }

    @GetMapping("/{userId}/info")
    @Operation(summary = "获取用户信息（Feign降级）", description = "供Feign客户端调用的用户信息接口")
    public ApiResults<com.frog.common.dto.user.UserInfo> getUserInfo(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID userId) {
        com.frog.common.dto.user.UserInfo userInfo = userService.getUserInfo(userId);
        return ApiResults.success(userInfo);
    }

    @GetMapping("/{userId}/roles")
    @Operation(summary = "获取用户角色（Feign降级）", description = "供Feign客户端调用的角色查询接口")
    public ApiResults<java.util.Set<String>> findRolesByUserId(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID userId) {
        java.util.Set<String> roles = permissionService.getUserRoles(userId);
        return ApiResults.success(roles);
    }

    @GetMapping("/{userId}/permissions")
    @Operation(summary = "获取用户权限（Feign降级）", description = "供Feign客户端调用的权限查询接口")
    public ApiResults<java.util.Set<String>> findPermissionsByUserId(
            @Parameter(description = "用户 ID", required = true) @PathVariable UUID userId) {
        java.util.Set<String> permissions = permissionService.getUserPermissions(userId);
        return ApiResults.success(permissions);
    }
}
