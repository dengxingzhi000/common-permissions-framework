package com.frog.system.service.Impl;

import com.frog.common.config.SysConfigService;
import com.frog.common.exception.BusinessException;
import com.frog.common.response.ResultCode;
import com.frog.system.domain.entity.SysUser;
import com.frog.system.event.DataSyncEventPublisher;
import com.frog.system.mapper.SysUserMapper;
import com.frog.system.service.CrossDatabaseQueryService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SysUserServiceImplHardcodedUuidTest {

    @Mock SysUserMapper userMapper;
    @Mock CrossDatabaseQueryService crossDbService;
    @Mock PasswordEncoder passwordEncoder;
    @Mock DataSyncEventPublisher dataSyncEventPublisher;
    @Mock SysConfigService sysConfigService;
    @InjectMocks SysUserServiceImpl service;

    @Test
    void delete_superAdminUser_throws() {
        UUID adminId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d4875");
        when(sysConfigService.getUuid("super_admin_user_id")).thenReturn(adminId);
        when(userMapper.selectById(adminId))
                .thenReturn(new SysUser().setId(adminId).setUsername("admin"));

        assertThatThrownBy(() -> service.deleteUser(adminId))
                .isInstanceOf(BusinessException.class)
                .extracting("code")
                .isEqualTo(ResultCode.USER_CANNOT_DELETE_ADMIN.getCode());
    }

    @Test
    void delete_superAdminUser_lookupReturnsNull_doesNotThrowForAdminCheck() {
        UUID adminId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d4875");
        when(sysConfigService.getUuid("super_admin_user_id")).thenReturn(null);
        when(userMapper.selectById(adminId))
                .thenReturn(new SysUser().setId(adminId).setUsername("admin"));
        when(userMapper.deleteById(adminId)).thenReturn(1);

        service.deleteUser(adminId);
    }
}