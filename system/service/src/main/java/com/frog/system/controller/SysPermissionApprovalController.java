package com.frog.system.controller;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.frog.common.domain.PageResult;
import com.frog.common.log.annotation.AuditLog;
import com.frog.common.dto.approval.ApprovalDTO;
import com.frog.common.dto.approval.ApprovalProcessDTO;
import com.frog.common.response.ApiResults;
import com.frog.system.service.ISysPermissionApprovalService;
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

import java.util.UUID;

/**
 * 权限申请审批控制器
 *
 * @author Deng
 * @since 2025-11-03
 */
@RestController
@RequestMapping("/v1/api/system/approvals")
@RequiredArgsConstructor
@Tag(name = "权限审批模块", description = "权限申请审批流程相关接口，包括申请提交、审批处理、申请撤回等功能")
public class SysPermissionApprovalController {
    private final ISysPermissionApprovalService approvalService;

    /**
     * 提交权限申请
     */
    @PostMapping("/submit")
    @Operation(summary = "提交权限申请", description = "用户提交权限申请，等待审批人审批")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "提交成功，返回审批ID"),
            @ApiResponse(responseCode = "400", description = "请求参数校验失败")
    })
    @AuditLog(
            operation = "提交权限申请",
            businessType = "APPROVAL",
            riskLevel = 3
    )
    public ApiResults<UUID> submitApproval(
            @Parameter(description = "审批申请信息", required = true) @Validated @RequestBody ApprovalDTO approvalDTO) {
        UUID approvalId = approvalService.submitApproval(approvalDTO);

        return ApiResults.success("申请已提交，等待审批", approvalId);
    }

    /**
     * 审批处理
     */
    @PostMapping("/{id}/process")
    @PreAuthorize("hasAnyAuthority('system:approval:process', 'system:admin')")
    @Operation(summary = "审批处理", description = "审批人对权限申请进行审批（通过或拒绝）")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "审批处理成功"),
            @ApiResponse(responseCode = "400", description = "请求参数校验失败"),
            @ApiResponse(responseCode = "404", description = "审批单不存在"),
            @ApiResponse(responseCode = "403", description = "无权限访问")
    })
    @AuditLog(
            operation = "审批处理",
            businessType = "APPROVAL",
            riskLevel = 4
    )
    public ApiResults<String> processApproval(
            @Parameter(description = "审批 ID", required = true) @PathVariable UUID id,
            @Parameter(description = "审批处理信息", required = true) @Validated @RequestBody ApprovalProcessDTO dto) {
        approvalService.processApproval(id, dto);

        return ApiResults.success(dto.getApproved() ? "审批通过" : "审批拒绝");
    }

    /**
     * 撤回申请
     */
    @PostMapping("/{id}/withdraw")
    @Operation(summary = "撤回申请", description = "申请人撤回待审批的权限申请")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "撤回成功"),
            @ApiResponse(responseCode = "404", description = "审批单不存在"),
            @ApiResponse(responseCode = "400", description = "审批单已处理，无法撤回")
    })
    @AuditLog(
            operation = "撤回申请",
            businessType = "APPROVAL",
            riskLevel = 2
    )
    public ApiResults<String> withdrawApproval(
            @Parameter(description = "审批 ID", required = true) @PathVariable UUID id) {
        approvalService.withdrawApproval(id);

        return ApiResults.success("申请已撤回");
    }

    /**
     * 查询待我审批的列表
     */
    @GetMapping("/pending")
    @Operation(summary = "待我审批的列表", description = "分页查询当前用户待审批的权限申请列表")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功",
                    content = @Content(schema = @Schema(implementation = PageResult.class)))
    })
    public ApiResults<PageResult<ApprovalDTO>> getPendingApprovals(
            @Parameter(description = "页码", example = "1") @RequestParam(defaultValue = "1") Integer page,
            @Parameter(description = "每页大小", example = "10") @RequestParam(defaultValue = "10") Integer size) {
        Page<ApprovalDTO> result = approvalService.getPendingApprovals(page, size);

        return ApiResults.success(PageResult.of(result));
    }

    /**
     * 查询我的申请历史
     */
    @GetMapping("/my-applications")
    @Operation(summary = "我的申请历史", description = "分页查询当前用户的所有权限申请历史记录")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功",
                    content = @Content(schema = @Schema(implementation = PageResult.class)))
    })
    public ApiResults<PageResult<ApprovalDTO>> getMyApplications(
            @Parameter(description = "页码", example = "1") @RequestParam(defaultValue = "1") Integer page,
            @Parameter(description = "每页大小", example = "10") @RequestParam(defaultValue = "10") Integer size) {
        Page<ApprovalDTO> result = approvalService.getMyApplications(page, size);

        return ApiResults.success(PageResult.of(result));
    }

    /**
     * 查询审批详情
     */
    @GetMapping("/{id}")
    @Operation(summary = "审批详情", description = "根据审批 ID查询审批单详细信息")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "查询成功"),
            @ApiResponse(responseCode = "404", description = "审批单不存在")
    })
    public ApiResults<ApprovalDTO> getApprovalDetail(
            @Parameter(description = "审批 ID", required = true) @PathVariable UUID id) {
        ApprovalDTO detail = approvalService.getApprovalDetail(id);

        return ApiResults.success(detail);
    }
}