package com.frog.system.controller;

import com.frog.common.dto.dept.DeptDTO;
import com.frog.common.log.annotation.AuditLog;
import com.frog.common.response.ApiResults;
import com.frog.system.service.ISysDeptService;
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
import java.util.UUID;

/**
 * <p>
 * 部门表 前端控制器
 * </p>
 *
 * @author author
 * @since 2025-11-07
 */
@RestController
@RequestMapping("/v1/api/system/depts")
@RequiredArgsConstructor
@Tag(name = "部门管理", description = "组织架构部门管理相关接口，支持树形结构的部门增删改查")
public class SysDeptController {
    private final ISysDeptService deptService;

    @GetMapping("/tree")
    @PreAuthorize("hasAuthority('system:dept:list')")
    @Operation(summary = "查询部门树", description = "获取组织架构树形结构，包含所有部门的层级关系")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    public ApiResults<List<DeptDTO>> tree() {
        List<DeptDTO> tree = deptService.getDeptTree();

        return ApiResults.success(tree);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('system:dept:add')")
    @Operation(summary = "新增部门", description = "创建新的组织部门")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "创建成功"),
            @ApiResponse(responseCode = "400", description = "请求参数校验失败"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "新增部门",
            businessType = "DEPT",
            riskLevel = 3
    )
    public ApiResults<Void> add(
            @Parameter(description = "部门信息", required = true) @Validated @RequestBody DeptDTO deptDTO) {
        deptService.addDept(deptDTO);

        return ApiResults.success();
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('system:dept:edit')")
    @Operation(summary = "修改部门", description = "更新部门信息")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "更新成功"),
            @ApiResponse(responseCode = "400", description = "请求参数校验失败"),
            @ApiResponse(responseCode = "404", description = "部门不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "修改部门",
            businessType = "DEPT",
            riskLevel = 3
    )
    public ApiResults<Void> update(
            @Parameter(description = "部门 ID", required = true) @PathVariable UUID id,
            @Parameter(description = "部门信息", required = true) @Validated @RequestBody DeptDTO deptDTO) {
        deptDTO.setId(id);
        deptService.updateDept(deptDTO);

        return ApiResults.success();
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('system:dept:delete')")
    @Operation(summary = "删除部门", description = "删除指定部门（软删除），如果部门下有子部门或用户，则无法删除")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "删除成功"),
            @ApiResponse(responseCode = "404", description = "部门不存在"),
            @ApiResponse(responseCode = "400", description = "部门下有子部门或用户，无法删除"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "删除部门",
            businessType = "DEPT",
            riskLevel = 4
    )
    public ApiResults<Void> delete(
            @Parameter(description = "部门 ID", required = true) @PathVariable UUID id) {
        deptService.deleteDept(id);

        return ApiResults.success();
    }
}
