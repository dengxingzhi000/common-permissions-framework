package com.frog.system.service.Impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.frog.common.config.SysConfigService;
import com.frog.common.exception.BusinessException;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.frog.common.dto.role.RoleDTO;
import com.frog.common.web.util.SecurityUtils;
import com.frog.system.domain.entity.SysRole;
import com.frog.system.event.DataSyncEventPublisher;
import com.frog.system.mapper.*;
import com.frog.system.service.ISysRoleService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * <p>
 * 角色表 服务实现类
 * </p>
 *
 * @author author
 * @since 2025-10-15
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SysRoleServiceImpl extends ServiceImpl<SysRoleMapper, SysRole> implements ISysRoleService {
    private final SysRoleMapper roleMapper;
    private final SysUserRoleMapper userRoleMapper;
    private final DataSyncEventPublisher dataSyncEventPublisher;
    private final SysRolePermissionMapper rolePermissionMapper;
    private final SysRoleDeptMapper roleDeptMapper;
    private final SysRoleDataRuleMapper roleDataRuleMapper;
    private final SysConfigService sysConfigService;

    /**
     * 分页查询角色列表
     */
    public Page<RoleDTO> listRoles(Integer pageNum, Integer pageSize, String roleName) {
        Page<SysRole> page = new Page<>(pageNum, pageSize);

        LambdaQueryWrapper<SysRole> wrapper = new LambdaQueryWrapper<>();
        wrapper.like(roleName != null && !roleName.isEmpty(), SysRole::getRoleName, roleName)
                .orderByAsc(SysRole::getSortOrder)
                .orderByDesc(SysRole::getCreateTime);

        Page<SysRole> rolePage = roleMapper.selectPage(page, wrapper);

        // 转换为 DTO
        Page<RoleDTO> roleDTOPage = new Page<>(pageNum, pageSize, rolePage.getTotal());
        List<RoleDTO> roleDTOs = rolePage.getRecords().stream()
                .map(this::convertToRoleDTO)
                .collect(Collectors.toList());
        roleDTOPage.setRecords(roleDTOs);

        return roleDTOPage;
    }

    /**
     * 查询所有角色
     */
    @Cacheable(
            value = "roles",
            key = "'all'"
    )
    public List<RoleDTO> listAllRoles() {
        LambdaQueryWrapper<SysRole> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(SysRole::getStatus, 1)
                .orderByAsc(SysRole::getSortOrder);

        List<SysRole> roles = roleMapper.selectList(wrapper);
        return roles.stream()
                .map(this::convertToRoleDTO)
                .collect(Collectors.toList());
    }

    /**
     * 根据 ID查询角色
     */
    @Cacheable(
            value = "role",
            key = "#id"
    )
    public RoleDTO getRoleById(UUID id) {
        SysRole role = roleMapper.selectById(id);
        if (role == null) {
            throw new BusinessException("角色不存在");
        }

        RoleDTO roleDTO = convertToRoleDTO(role);

        // 查询角色权限
        List<UUID> permissionIds = rolePermissionMapper.findPermissionIdsByRoleId(id);
        roleDTO.setPermissionIds(permissionIds);

        // 查询拥有该角色的用户数
        Integer userCount = userRoleMapper.countUsersByRoleId(id);
        roleDTO.setUserCount(userCount);

        return roleDTO;
    }

    /**
     * 新增角色
     */
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(
            value = {"role", "roles", "userRoles"},
            allEntries = true
    )
    public void addRole(RoleDTO roleDTO) {
        // 检查角色编码是否存在
        if (roleMapper.existsByRoleCode(roleDTO.getRoleCode())) {
            throw new BusinessException("角色编码已存在");
        }

        SysRole role = new SysRole();
        BeanUtils.copyProperties(roleDTO, role);

        roleMapper.insert(role);

        // 分配权限
        if (roleDTO.getPermissionIds() != null && !roleDTO.getPermissionIds().isEmpty()) {
            rolePermissionMapper.batchInsertRolePermissions(role.getId(), roleDTO.getPermissionIds(),
                    SecurityUtils.getCurrentUserUuid().orElse(null));
        }

        // Publish sync event for redundancy update
        dataSyncEventPublisher.publishRoleCreated(role);

        log.info("Role created: {}, by: {}", role.getRoleCode(), SecurityUtils.getCurrentUsername());
    }

    /**
     * 修改角色
     */
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(
            value = {"role", "roles", "userRoles", "userPermissions"},
            allEntries = true
    )
    public void updateRole(RoleDTO roleDTO) {
        SysRole existRole = roleMapper.selectById(roleDTO.getId());
        if (existRole == null) {
            throw new BusinessException("角色不存在");
        }

        // 不能修改超级管理员角色
        UUID superAdminRoleId = sysConfigService.getUuid("super_admin_role_id");
        if (superAdminRoleId != null && existRole.getId().equals(superAdminRoleId)) {
            throw new BusinessException("不能修改超级管理员角色");
        }

        SysRole role = new SysRole();
        BeanUtils.copyProperties(roleDTO, role);

        roleMapper.updateById(role);

        // Publish sync event for redundancy update
        SysRole updatedRole = roleMapper.selectById(role.getId());
        dataSyncEventPublisher.publishRoleUpdated(updatedRole);

        log.info("Role updated: {}, by: {}", role.getRoleCode(), SecurityUtils.getCurrentUsername());
    }

    /**
     * 删除角色
     * <p>
     * 删除角色时会同时清理以下关联数据：
     * <ul>
     *   <li>sys_role_permission - 角色权限关联</li>
     *   <li>sys_role_dept - 角色部门关联（自定义数据权限）</li>
     *   <li>sys_role_data_rule - 角色数据权限规则关联</li>
     * </ul>
     */
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(
            value = {"role", "roles", "userRoles", "userPermissions"},
            allEntries = true
    )
    public void deleteRole(UUID id) {
        SysRole role = roleMapper.selectById(id);
        if (role == null) {
            throw new BusinessException("角色不存在");
        }

        // 不能删除超级管理员角色
        UUID superAdminRoleId = sysConfigService.getUuid("super_admin_role_id");
        if (superAdminRoleId != null && role.getId().equals(superAdminRoleId)) {
            throw new BusinessException("不能删除超级管理员角色");
        }

        // 检查是否有用户使用该角色
        Integer userCount = userRoleMapper.countUsersByRoleId(id);
        if (userCount > 0) {
            throw new BusinessException("该角色下还有 " + userCount + " 个用户，不能删除");
        }

        // 1. 删除角色权限关联 (sys_role_permission)
        rolePermissionMapper.deleteRolePermissions(id);

        // 2. 删除角色部门关联 (sys_role_dept) - 自定义数据权限范围
        roleDeptMapper.deleteRoleDepts(id);

        // 3. 删除角色数据权限规则关联 (sys_role_data_rule)
        roleDataRuleMapper.deleteRoleDataRules(id);

        // 4. 删除角色记录
        roleMapper.deleteById(id);

        // 5. 发布同步事件用于冗余数据更新
        dataSyncEventPublisher.publishRoleDeleted(id);

        log.info("Role deleted: {}, by: {}", role.getRoleCode(), SecurityUtils.getCurrentUsername());
    }

    /**
     * 授权权限
     */
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(
            value = {"role", "userRoles", "userPermissions", "userInfo"},
            allEntries = true
    )
    public void grantPermissions(UUID roleId, List<UUID> permissionIds) {
        SysRole role = roleMapper.selectById(roleId);
        if (role == null) {
            throw new BusinessException("角色不存在");
        }

        // 删除原有权限
        rolePermissionMapper.deleteRolePermissions(roleId);

        // 分配新权限
        if (permissionIds != null && !permissionIds.isEmpty()) {
            rolePermissionMapper.batchInsertRolePermissions(roleId, permissionIds,
                    SecurityUtils.getCurrentUserUuid().orElse(null));
        }

        log.info("Permissions granted to role: {}, permissions count: {}, by: {}",
                role.getRoleCode(), permissionIds != null ? permissionIds.size() : 0,
                SecurityUtils.getCurrentUsername());
    }

    /**
     * 查询角色权限 ID列表
     */
    @Cacheable(
            value = "rolePermissions",
            key = "#roleId"
    )
    public List<UUID> getRolePermissionIds(UUID roleId) {
        return rolePermissionMapper.findPermissionIdsByRoleId(roleId);
    }

    private RoleDTO convertToRoleDTO(SysRole role) {
        RoleDTO roleDTO = new RoleDTO();
        BeanUtils.copyProperties(role, roleDTO);
        return roleDTO;
    }
}
