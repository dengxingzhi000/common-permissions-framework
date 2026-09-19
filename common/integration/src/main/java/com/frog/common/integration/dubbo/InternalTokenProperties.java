package com.frog.common.integration.dubbo;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "dubbo.internal-token")
public class InternalTokenProperties {
    private boolean enabled = true;
    private String sharedSecret;
    private int ttlSeconds = 60;
}
