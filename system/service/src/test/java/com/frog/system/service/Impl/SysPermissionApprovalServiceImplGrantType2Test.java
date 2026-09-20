package com.frog.system.service.Impl;

import com.frog.system.domain.entity.SysPermissionApproval;
import com.frog.system.mapper.SysPermissionApprovalMapper;
import com.frog.system.notification.NotificationService;
import com.frog.system.service.CrossDatabaseQueryService;
import com.frog.system.service.ISysUserPermissionService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Method;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class SysPermissionApprovalServiceImplGrantType2Test {

    @Mock
    SysPermissionApprovalMapper approvalMapper;
    @Mock
    NotificationService notificationService;
    @Mock
    CrossDatabaseQueryService crossDatabaseQueryService;
    @Mock
    ISysUserPermissionService userPermService;

    @InjectMocks
    SysPermissionApprovalServiceImpl service;

    @Test
    void grantPermissions_type2_callsUserPermissionServiceGrant() throws Exception {
        UUID targetUser = UUID.randomUUID();
        UUID approver = UUID.randomUUID();
        UUID permId = UUID.randomUUID();
        UUID approvalId = UUID.randomUUID();

        SysPermissionApproval approval = SysPermissionApproval.builder()
                .id(approvalId)
                .targetUserId(targetUser)
                .approvalType(2)
                .permissionIds(new UUID[]{permId})
                .build();

        Method m = SysPermissionApprovalServiceImpl.class
                .getDeclaredMethod("grantPermissions", SysPermissionApproval.class);
        m.setAccessible(true);
        m.invoke(service, approval);

        ArgumentCaptor<Set<UUID>> permIdsCaptor = ArgumentCaptor.forClass(Set.class);
        ArgumentCaptor<UUID> userIdCaptor = ArgumentCaptor.forClass(UUID.class);
        ArgumentCaptor<UUID> grantedByCaptor = ArgumentCaptor.forClass(UUID.class);
        ArgumentCaptor<String> reasonCaptor = ArgumentCaptor.forClass(String.class);

        org.mockito.Mockito.verify(userPermService)
                .grant(userIdCaptor.capture(), permIdsCaptor.capture(),
                        grantedByCaptor.capture(), reasonCaptor.capture());

        assertThat(userIdCaptor.getValue()).isEqualTo(targetUser);
        assertThat(permIdsCaptor.getValue()).containsExactly(permId);
        assertThat(grantedByCaptor.getValue()).isNotNull();
        assertThat(reasonCaptor.getValue()).contains(approvalId.toString());
    }

    @Test
    void grantPermissions_type2_nullPermissionIds_isNoop() throws Exception {
        SysPermissionApproval approval = SysPermissionApproval.builder()
                .id(UUID.randomUUID())
                .targetUserId(UUID.randomUUID())
                .approvalType(2)
                .permissionIds(null)
                .build();

        Method m = SysPermissionApprovalServiceImpl.class
                .getDeclaredMethod("grantPermissions", SysPermissionApproval.class);
        m.setAccessible(true);
        m.invoke(service, approval);

        org.mockito.Mockito.verifyNoInteractions(userPermService);
    }
}
