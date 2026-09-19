package com.frog.common.integration.config;

import com.frog.common.integration.dubbo.InternalTokenFilter;
import com.frog.common.integration.dubbo.InternalTokenProperties;
import com.frog.common.integration.dubbo.InternalTokenSigner;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(InternalTokenProperties.class)
@ConditionalOnProperty(prefix = "dubbo.internal-token", name = "shared-secret")
public class InternalTokenAutoConfiguration {

    @Bean
    public InternalTokenSigner internalTokenSigner(InternalTokenProperties props) {
        return new InternalTokenSigner(props);
    }

    @Bean
    public InternalTokenFilter providerInternalTokenFilter(
            InternalTokenSigner signer,
            InternalTokenProperties props,
            @Value("${spring.application.name:unknown}") String appName) {
        return new InternalTokenFilter(signer, props, appName);
    }
}
