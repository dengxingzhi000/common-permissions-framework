package com.frog.auth.migration;

import com.frog.common.security.util.JwtUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtMigrationShimTest {

    @Mock JwtUtils jwtUtils;
    @InjectMocks JwtMigrationShim shim;

    @Test
    void extractUserIdFromLegacyHs512_returnsUserId() {
        UUID expectedId = UUID.randomUUID();
        when(jwtUtils.getUserIdFromToken("legacy.token")).thenReturn(expectedId);
        assertThat(shim.extractUserIdFromLegacyHs512("legacy.token")).isEqualTo(expectedId);
    }
}