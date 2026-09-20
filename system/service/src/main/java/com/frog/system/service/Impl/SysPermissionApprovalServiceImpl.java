package com.frog.system.service.Impl;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.frog.common.exception.BusinessException;
import com.frog.common.util.UUIDv7Util;
import com.frog.common.dto.approval.ApprovalDTO;
import com.frog.common.dto.approval.ApprovalProcessDTO;
import com.frog.common.web.util.SecurityUtils;
import com.frog.system.domain.entity.SysPermissionApproval;
import com.frog.system.domain.entity.SysUser;
import com.frog.system.mapper.SysPermissionApprovalMapper;
import com.frog.system.service.CrossDatabaseQueryService;
import com.frog.system.service.ISysPermissionApprovalService;
import com.frog.system.service.ISysUserPermissionService;
import com.frog.system.notification.NotificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

/**
 * 权限申请审批服务实现
 *
 * @author Deng
 * @since 2025-11-03
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SysPermissionApprovalServiceImpl
        extends ServiceImpl<SysPermissionApprovalMapper, SysPermissionApproval>
        implements ISysPermissionApprovalService {
    private final SysPermissionApprovalMapper approvalMapper;
    private final NotificationService notificationService;
    private final CrossDatabaseQueryService crossDatabaseQueryService;
    private final ISysUserPermissionService sysUserPermissionService;

    /** 系统管理员角色编码 */
    private static final String ROLE_ADMIN = "ROLE_ADMIN";
    /** 超级管理员角色编码 */
    private static final String ROLE_SUPER_ADMIN = "ROLE_SUPER_ADMIN";

    /**
     * 提交权限申请
     */
    @Override
    @Transactional(rollbackFor = Exception.class)
    public UUID submitApproval(ApprovalDTO dto) {
        UUID currentUserId = SecurityUtils.getCurrentUserUuid().orElse(null);

        // 1. 检查是否有重复的待审批申请
        if (approvalMapper.existsPendingApplication(
                currentUserId, dto.getTargetUserId(), dto.getApprovalType())) {
            throw new BusinessException("您已有相同的申请正在审批中");
        }

        // 2. 构建审批实体
        SysPermissionApproval approval = SysPermissionApproval.builder()
                .id(UUIDv7Util.generate())
                .applicantId(currentUserId)
                .approvalType(dto.getApprovalType())
                .targetUserId(dto.getTargetUserId())
                .roleIds(dto.getRoleIds() != null ?
                        dto.getRoleIds().toArray(new UUID[0]) : null)
                .permissionIds(dto.getPermissionIds() != null ?
                        dto.getPermissionIds().toArray(new UUID[0]) : null)
                .effectiveTime(dto.getEffectiveTime())
                .expireTime(dto.getExpireTime())
                .applyReason(dto.getApplyReason())
                .businessJustification(dto.getBusinessJustification())
                .approvalStatus(0) // 待审批
                .build();

        // 3. 构建审批链
        List<UUID> approverIds = buildApprovalChain(dto.getApprovalType(), currentUserId);
        List<Map<String, Object>> approvalChain = approverIds.stream()
                .map(id -> {
                    Map<String, Object> node = new HashMap<>();
                    node.put("approverId", id.toString());
                    node.put("status", "pending");
                    return node;
                })
                .collect(Collectors.toList());
        approval.setApprovalChain(approvalChain);

        // 4. 设置第一个审批人
        if (!approverIds.isEmpty()) {
            approval.setCurrentApproverId(approverIds.getFirst());
        }

        // 5. 保存申请
        approvalMapper.insert(approval);

        log.info("Permission approval submitted: id={}, applicant={}, type={}",
                approval.getId(), currentUserId, dto.getApprovalType());

        // 6. 发送通知给第一个审批人
        sendApprovalNotification(approval);

        return approval.getId();
    }

    /**
     * 审批处理
     */
    @Override
    @Transactional(rollbackFor = Exception.class)
    public void processApproval(UUID approvalId, ApprovalProcessDTO dto) {
        UUID currentUserId = SecurityUtils.getCurrentUserUuid().orElse(null);

        // 1. 查询审批记录
        SysPermissionApproval approval = approvalMapper.selectById(approvalId);
        if (approval == null) {
            throw new BusinessException("审批记录不存在");
        }

        // 2. 验证审批权限
        if (!Objects.equals(currentUserId, approval.getCurrentApproverId())) {
            throw new BusinessException("您不是当前审批人");
        }

        // 3. 验证审批状态
        if (approval.getApprovalStatus() != 0 && approval.getApprovalStatus() != 1) {
            throw new BusinessException("该申请已被处理");
        }

        // 4. 处理审批
        if (dto.getApproved()) {
            handleApprove(approval, currentUserId);
        } else {
            handleReject(approval, dto, currentUserId);
        }
    }

    /**
     * 处理通过
     */
    private void handleApprove(SysPermissionApproval approval, UUID approverId) {
        // 1. 从审批链中提取审批人ID列表
        List<Map<String, Object>> approvalChain = approval.getApprovalChain();
        List<UUID> approverIds = approvalChain.stream()
                .map(node -> UUID.fromString((String) node.get("approverId")))
                .toList();

        int currentIndex = approverIds.indexOf(approverId);

        // 2. 判断是否还有下一级审批人
        if (currentIndex < approverIds.size() - 1) {
            // 还有下一级，转给下一个审批人
            UUID nextApprover = approverIds.get(currentIndex + 1);
            approvalMapper.updateCurrentApprover(approval.getId(), nextApprover);

            log.info("Approval forwarded to next approver: id={}, next={}",
                    approval.getId(), nextApprover);

            // 发送通知给下一个审批人
            sendApprovalNotification(approval);
        } else {
            // 最后一级审批人，批准通过
            approvalMapper.updateApprovalStatus(
                    approval.getId(), 2, approverId, null);

            log.info("Approval granted: id={}, approver={}",
                    approval.getId(), approverId);

            // 执行权限授予
            grantPermissions(approval);

            // 通知申请人
            sendResultNotification(approval, true);
        }
    }

    /**
     * 处理拒绝
     */
    private void handleReject(SysPermissionApproval approval,
                              ApprovalProcessDTO dto, UUID approverId) {
        approvalMapper.updateApprovalStatus(
                approval.getId(), 3, approverId, dto.getRejectReason());

        log.info("Approval rejected: id={}, approver={}, reason={}",
                approval.getId(), approverId, dto.getRejectReason());

        // 通知申请人
        sendResultNotification(approval, false);
    }

    /**
     * 执行权限授予
     * <p>
     * 通过 CrossDatabaseQueryService 跨库操作 db_permission
     */
    private void grantPermissions(SysPermissionApproval approval) {
        UUID targetUserId = approval.getTargetUserId();
        UUID currentUserId = SecurityUtils.getCurrentUserUuid().orElse(null);

        switch (approval.getApprovalType()) {
            case 1 -> // 角色申请（永久授权）
                    Optional.ofNullable(approval.getRoleIds())
                            .ifPresent(roleIdsArray -> {
                                List<UUID> roleIds = Arrays.asList(roleIdsArray);
                                crossDatabaseQueryService.batchInsertUserRoles(targetUserId, roleIds, currentUserId);
                                log.info("Permanent roles granted: userId={}, roleIds={}", targetUserId, roleIds);
                            });

            case 2 -> { // 权限申请 — 直接权限授予(落地 sys_user_permission)
                if (approval.getPermissionIds() == null || approval.getPermissionIds().length == 0) {
                    log.debug("Type=2 approval has no permissionIds, skipping grant: id={}", approval.getId());
                    break;
                }
                Set<UUID> permIds = Arrays.stream(approval.getPermissionIds())
                        .collect(Collectors.toSet());
                sysUserPermissionService.grant(targetUserId, permIds, currentUserId,
                        "approval: " + approval.getId());
                log.info("Direct permissions granted via approval: approvalId={}, targetUser={}, permIds={}",
                        approval.getId(), targetUserId, permIds);
            }

            case 3 -> // 临时授权（带过期时间）
                    Optional.ofNullable(approval.getRoleIds())
                            .ifPresent(roleIdsArray -> {
                                List<UUID> roleIds = Arrays.asList(roleIdsArray);
                                crossDatabaseQueryService.batchInsertTemporaryUserRoles(
                                        targetUserId,
                                        roleIds,
                                        approval.getEffectiveTime(),
                                        approval.getExpireTime(),
                                        currentUserId
                                );
                                log.info("Temporary roles granted: userId={}, roleIds={}, expireTime={}",
                                        targetUserId, roleIds, approval.getExpireTime());
                            });

            default -> throw new BusinessException("未知的审批类型: " + approval.getApprovalType());
        }
    }

    /**
     * 撤回申请
     */
    @Override
    @Transactional(rollbackFor = Exception.class)
    public void withdrawApproval(UUID approvalId) {
        UUID currentUserId = SecurityUtils.getCurrentUserUuid().orElse(null);

        SysPermissionApproval approval = approvalMapper.selectById(approvalId);
        if (approval == null) {
            throw new BusinessException("审批记录不存在");
        }

        // 验证权限：只有申请人可以撤回
        if (!Objects.equals(currentUserId, approval.getApplicantId())) {
            throw new BusinessException("您无权撤回该申请");
        }

        // 验证状态：只有待审批的可以撤回
        if (approval.getApprovalStatus() != 0 && approval.getApprovalStatus() != 1) {
            throw new BusinessException("该申请已被处理，无法撤回");
        }

        // 更新状态为已撤回
        approvalMapper.updateApprovalStatus(approvalId, 4, currentUserId, "申请人撤回");

        log.info("Approval withdrawn: id={}, applicant={}", approvalId, currentUserId);
    }

    /**
     * 查询待我审批的列表
     */
    @Override
    public Page<ApprovalDTO> getPendingApprovals(Integer pageNum, Integer pageSize) {
        UUID currentUserId = SecurityUtils.getCurrentUserUuid().orElse(null);
        Page<SysPermissionApproval> page = new Page<>(pageNum, pageSize);

        Page<SysPermissionApproval> result = approvalMapper.selectPendingApprovals(
                page, currentUserId);

        return convertToDTO(result);
    }

    /**
     * 查询我的申请历史
     */
    @Override
    public Page<ApprovalDTO> getMyApplications(Integer pageNum, Integer pageSize) {
        UUID currentUserId = SecurityUtils.getCurrentUserUuid().orElse(null);
        Page<SysPermissionApproval> page = new Page<>(pageNum, pageSize);

        Page<SysPermissionApproval> result = approvalMapper.selectUserApplyHistory(
                page, currentUserId);

        return convertToDTO(result);
    }

    /**
     * 构建审批链
     * 根据申请类型和申请人确定审批链路
     * 审批规则：
     * - 角色申请(type=1): 部门经理 -> 系统管理员
     * - 权限申请(type=2): 部门经理 -> 系统管理员
     * - 临时授权(type=3): 部门经理（如果是高风险权限，还需要系统管理员）
     * <p>
     * 通过 CrossDatabaseQueryService 跨库查询 db_user 和 db_org
     */
    private List<UUID> buildApprovalChain(Integer approvalType, UUID applicantId) {
        List<UUID> chain = new ArrayList<>();

        // 通过 CrossDatabaseQueryService 跨库查询申请人信息 (db_user)
        SysUser applicant = crossDatabaseQueryService.getUserBasicInfo(applicantId);
        if (applicant == null) {
            log.warn("Cannot build approval chain: applicant not found, id={}", applicantId);
            return chain;
        }

        // 1. 获取部门经理（如果有）- 通过 CrossDatabaseQueryService 跨库查询 (db_org)
        UUID deptManager = getDeptManager(applicant.getDeptId());
        if (deptManager != null && !deptManager.equals(applicantId)) {
            // 部门经理不能审批自己的申请
            chain.add(deptManager);
            log.debug("Added dept manager to approval chain: {}", deptManager);
        }

        // 2. 根据申请类型决定是否需要系统管理员
        if (approvalType == 1 || approvalType == 2) {
            // 角色申请和权限申请需要系统管理员
            UUID sysAdmin = getSystemAdmin();
            if (sysAdmin != null && !sysAdmin.equals(applicantId) && !chain.contains(sysAdmin)) {
                chain.add(sysAdmin);
                log.debug("Added system admin to approval chain: {}", sysAdmin);
            }
        } else if (approvalType == 3) {
            // 临时授权：检查是否涉及高风险权限
            // 如果没有部门经理，直接找系统管理员
            if (chain.isEmpty()) {
                UUID sysAdmin = getSystemAdmin();
                if (sysAdmin != null && !sysAdmin.equals(applicantId)) {
                    chain.add(sysAdmin);
                }
            }
        }

        // 3. 如果审批链为空（没有部门经理和系统管理员），使用超级管理员
        if (chain.isEmpty()) {
            UUID superAdmin = getSuperAdmin();
            if (superAdmin != null && !superAdmin.equals(applicantId)) {
                chain.add(superAdmin);
                log.debug("Fallback to super admin: {}", superAdmin);
            }
        }

        log.info("Built approval chain for applicant {}: {} approvers", applicantId, chain.size());
        return chain;
    }

    /**
     * 获取部门负责人
     * <p>
     * 通过 CrossDatabaseQueryService 跨库查询 db_org
     */
    private UUID getDeptManager(UUID deptId) {
        if (deptId == null) {
            return null;
        }
        return crossDatabaseQueryService.getDeptLeaderId(deptId);
    }

    /**
     * 获取系统管理员（第一个拥有 ROLE_ADMIN 角色的用户）
     */
    private UUID getSystemAdmin() {
        return crossDatabaseQueryService.findFirstUserIdByRoleCode(ROLE_ADMIN);
    }

    /**
     * 获取超级管理员（第一个拥有 ROLE_SUPER_ADMIN 角色的用户）
     */
    private UUID getSuperAdmin() {
        return crossDatabaseQueryService.findFirstUserIdByRoleCode(ROLE_SUPER_ADMIN);
    }

    /**
     * 发送审批通知
     * <p>
     * 通过 CrossDatabaseQueryService 跨库查询 db_user
     */
    private void sendApprovalNotification(SysPermissionApproval approval) {
        try {
            UUID approverId = approval.getCurrentApproverId();
            if (approverId == null) {
                log.warn("No current approver to notify for approval {}", approval.getId());
                return;
            }

            // 通过 CrossDatabaseQueryService 跨库查询审批人信息 (db_user)
            SysUser approver = crossDatabaseQueryService.getUserBasicInfo(approverId);
            if (approver == null) {
                log.warn("Approver not found: {}", approverId);
                return;
            }

            // 通过 CrossDatabaseQueryService 跨库查询申请人信息 (db_user)
            SysUser applicant = crossDatabaseQueryService.getUserBasicInfo(approval.getApplicantId());
            String applicantName = applicant != null ? applicant.getRealName() : "Unknown";

            // 构建通知参数
            Map<String, Object> params = new HashMap<>();
            params.put("approvalId", approval.getId().toString());
            params.put("applicantName", applicantName);
            params.put("approvalType", getApprovalTypeName(approval.getApprovalType()));
            params.put("applyReason", approval.getApplyReason());

            // 发送通知
            notificationService.sendNotification(
                    approver.getUsername(),
                    approver.getEmail(),
                    "APPROVAL_PENDING",
                    "您有新的权限审批待处理",
                    params
            );

            log.info("Approval notification sent: id={}, approver={}",
                    approval.getId(), approverId);
        } catch (Exception e) {
            log.error("Failed to send approval notification: {}", e.getMessage(), e);
        }
    }

    /**
     * 发送审批结果通知
     * <p>
     * 通过 CrossDatabaseQueryService 跨库查询 db_user
     */
    private void sendResultNotification(SysPermissionApproval approval, boolean approved) {
        try {
            // 通过 CrossDatabaseQueryService 跨库查询申请人信息 (db_user)
            SysUser applicant = crossDatabaseQueryService.getUserBasicInfo(approval.getApplicantId());
            if (applicant == null) {
                log.warn("Applicant not found: {}", approval.getApplicantId());
                return;
            }

            // 构建通知参数
            Map<String, Object> params = new HashMap<>();
            params.put("approvalId", approval.getId().toString());
            params.put("approvalType", getApprovalTypeName(approval.getApprovalType()));
            params.put("result", approved ? "已批准" : "已拒绝");
            params.put("rejectReason", approval.getRejectReason());

            // 发送通知
            String templateCode = approved ? "APPROVAL_APPROVED" : "APPROVAL_REJECTED";
            String subject = approved ? "您的权限申请已批准" : "您的权限申请被拒绝";

            notificationService.sendNotification(
                    applicant.getUsername(),
                    applicant.getEmail(),
                    templateCode,
                    subject,
                    params
            );

            log.info("Approval result notification sent: id={}, result={}",
                    approval.getId(), approved ? "approved" : "rejected");
        } catch (Exception e) {
            log.error("Failed to send result notification: {}", e.getMessage(), e);
        }
    }

    /**
     * 获取审批类型名称
     */
    private String getApprovalTypeName(Integer approvalType) {
        return switch (approvalType) {
            case 1 -> "角色申请";
            case 2 -> "权限申请";
            case 3 -> "临时授权";
            default -> "未知类型";
        };
    }

    /**
     * 查询审批详情
     */
    @Override
    public ApprovalDTO getApprovalDetail(UUID approvalId) {
        SysPermissionApproval approval = approvalMapper.selectById(approvalId);
        if (approval == null) {
            throw new BusinessException("审批记录不存在");
        }

        return convertToDTO(approval);
    }

    /**
     * 转换为 DTO
     */
    private Page<ApprovalDTO> convertToDTO(Page<SysPermissionApproval> page) {
        Page<ApprovalDTO> dtoPage = new Page<>(
                page.getCurrent(), page.getSize(), page.getTotal());

        List<ApprovalDTO> records = page.getRecords().stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());

        dtoPage.setRecords(records);
        return dtoPage;
    }

    private ApprovalDTO convertToDTO(SysPermissionApproval entity) {
        ApprovalDTO approvalDTO = ApprovalDTO.builder()
                .id(entity.getId())
                .applicantId(entity.getApplicantId())
                .approvalType(entity.getApprovalType())
                .targetUserId(entity.getTargetUserId())
                .applyReason(entity.getApplyReason())
                .businessJustification(entity.getBusinessJustification())
                .approvalStatus(entity.getApprovalStatus())
                .effectiveTime(entity.getEffectiveTime())
                .expireTime(entity.getExpireTime())
                .approvedTime(entity.getApprovedTime())
                .rejectReason(entity.getRejectReason())
                .build();

        // 转换角色和权限 ID数组为List
        if (entity.getRoleIds() != null) {
            approvalDTO.setRoleIds(Arrays.asList(entity.getRoleIds()));
        }

        if (entity.getPermissionIds() != null) {
            approvalDTO.setPermissionIds(Arrays.asList(entity.getPermissionIds()));
        }

        return approvalDTO;
    }
}