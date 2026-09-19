package com.frog.common.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

class SysConfigServiceTest {

    @Mock SysConfigMapper mapper;
    @InjectMocks SysConfigService service;

    @BeforeEach
    void setup() { MockitoAnnotations.openMocks(this); }

    @Test
    void getString_returnsValueFromDb() {
        when(mapper.selectByKey("foo", null))
                .thenReturn(SysConfig.builder().configValue("bar").build());
        assertThat(service.getString("foo")).isEqualTo("bar");
    }

    @Test
    void getString_returnsNullWhenAbsent() {
        when(mapper.selectByKey("missing", null)).thenReturn(null);
        assertThat(service.getString("missing")).isNull();
    }

    @Test
    void getUuid_parsesValidUuid() {
        UUID u = UUID.randomUUID();
        when(mapper.selectByKey("k", null))
                .thenReturn(SysConfig.builder().configValue(u.toString()).build());
        assertThat(service.getUuid("k")).isEqualTo(u);
    }
}