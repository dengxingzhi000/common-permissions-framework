package com.frog.common.config;

import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SysConfigService {

    private final SysConfigMapper mapper;

    @Cacheable(value = "sysConfig", key = "#key + ':GLOBAL'", unless = "#result == null")
    public String getString(String key) {
        return getString(key, null);
    }

    @Cacheable(value = "sysConfig", key = "#key + ':' + (#tenantId == null ? 'GLOBAL' : #tenantId.toString())", unless = "#result == null")
    public String getString(String key, UUID tenantId) {
        SysConfig cfg = mapper.selectByKey(key, tenantId == null ? null : tenantId.toString());
        return cfg == null ? null : cfg.getConfigValue();
    }

    public UUID getUuid(String key) {
        String v = getString(key);
        return v == null ? null : UUID.fromString(v);
    }
}