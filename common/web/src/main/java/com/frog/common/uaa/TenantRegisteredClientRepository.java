package com.frog.common.uaa;

import com.frog.common.security.oauth2.SysRegisteredClientDTO;
import com.frog.system.api.ISysRegisteredClientService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;

/**
 * DB-backed {@link RegisteredClientRepository} — Phase 1.4。
 *
 * <p>从 {@code sys_registered_client} 表加载 OAuth2 客户端配置,
 * 替代 {@code AuthorizationServerConfig} 中硬编码的
 * {@code InMemoryRegisteredClientRepository}。
 *
 * <p>本类位于 {@code common/web},通过构造函数注入
 * {@link ISysRegisteredClientService}(接口位于 {@code system/api})。
 * 这种安排维持了模块依赖方向(
 * {@code common/*} 可以依赖 {@code system/api},不能依赖 {@code system/service})。
 *
 * <p>当前只读;{@link #save(RegisteredClient)} 暂未实现 — 应通过
 * SysRegisteredClientService 的 admin 接口进行写入,确保 UUID、status、
 * 默认 TTL 等字段在 service 层统一处理。
 *
 * @author Deng
 * @since 2026-09-23
 */
@Slf4j
@RequiredArgsConstructor
public class TenantRegisteredClientRepository implements RegisteredClientRepository {

    private final ISysRegisteredClientService clientService;

    @Override
    public void save(RegisteredClient registeredClient) {
        // Phase 1.4 仅支持读路径;写入应通过 SysRegisteredClientService 的 admin 接口。
        // 保留此方法的最小可观察行为,便于将来 admin 接口补齐后切换到 DB。
        throw new UnsupportedOperationException(
                "TenantRegisteredClientRepository.save() is not implemented in Phase 1.4. "
                        + "Use ISysRegisteredClientService.addClient() to register a new client.");
    }

    @Override
    public RegisteredClient findById(String id) {
        if (!StringUtils.hasText(id)) {
            return null;
        }
        Optional<SysRegisteredClientDTO> record = clientService
                .findOptionalByClientId(id);
        if (record.isEmpty()) {
            log.debug("RegisteredClient not found by id={}", id);
            return null;
        }
        return toRegisteredClient(record.get());
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        if (!StringUtils.hasText(clientId)) {
            return null;
        }
        SysRegisteredClientDTO record = clientService.findByClientId(clientId);
        if (record == null) {
            log.debug("RegisteredClient not found by clientId={}", clientId);
            return null;
        }
        Integer status = record.getStatus();
        if (status == null || status != 1) {
            log.warn("RegisteredClient is disabled: clientId={}, status={}",
                    clientId, status);
            return null;
        }
        return toRegisteredClient(record);
    }

    /**
     * DB DTO → Spring Authorization Server {@link RegisteredClient}。
     *
     * <p>字段映射严格遵循 {@code SysRegisteredClientDTO} 与
     * {@code RegisteredClient.Builder} 的对应关系。
     */
    RegisteredClient toRegisteredClient(SysRegisteredClientDTO src) {
        RegisteredClient.Builder builder = RegisteredClient.withId(src.getId().toString())
                .clientId(src.getClientId())
                .clientSecret(src.getClientSecretHash() == null ? "" : src.getClientSecretHash());

        // ClientAuthenticationMethod — 从 TEXT[] 解析
        if (src.getClientAuthMethods() != null) {
            for (String method : src.getClientAuthMethods()) {
                ClientAuthenticationMethod resolved = resolveClientAuthMethod(method);
                if (resolved != null) {
                    builder.clientAuthenticationMethod(resolved);
                }
            }
        }

        // AuthorizationGrantType — 从 TEXT[] 解析
        if (src.getGrantTypes() != null) {
            for (String grant : src.getGrantTypes()) {
                AuthorizationGrantType resolved = resolveGrantType(grant);
                if (resolved != null) {
                    builder.authorizationGrantType(resolved);
                }
            }
        }

        // Redirect URIs
        if (src.getRedirectUris() != null) {
            for (String uri : src.getRedirectUris()) {
                if (StringUtils.hasText(uri)) {
                    builder.redirectUri(uri);
                }
            }
        }

        // Post-logout redirect URIs
        if (src.getPostLogoutRedirectUris() != null) {
            for (String uri : src.getPostLogoutRedirectUris()) {
                if (StringUtils.hasText(uri)) {
                    builder.postLogoutRedirectUri(uri);
                }
            }
        }

        // Scopes
        if (src.getScopes() != null) {
            for (String scope : src.getScopes()) {
                if (StringUtils.hasText(scope)) {
                    builder.scope(scope);
                }
            }
        }

        // TokenSettings
        TokenSettings.Builder tokenBuilder = TokenSettings.builder();
        if (src.getAccessTokenTtlSeconds() != null && src.getAccessTokenTtlSeconds() > 0) {
            tokenBuilder.accessTokenTimeToLive(Duration.ofSeconds(src.getAccessTokenTtlSeconds()));
        }
        if (src.getRefreshTokenTtlSeconds() != null && src.getRefreshTokenTtlSeconds() > 0) {
            tokenBuilder.refreshTokenTimeToLive(Duration.ofSeconds(src.getRefreshTokenTtlSeconds()));
        }
        tokenBuilder.reuseRefreshTokens(false);
        builder.tokenSettings(tokenBuilder.build());

        // ClientSettings
        ClientSettings.Builder clientBuilder = ClientSettings.builder()
                .requireAuthorizationConsent(
                        Boolean.TRUE.equals(src.getRequireAuthorizationConsent()))
                .requireProofKey(Boolean.TRUE.equals(src.getRequireProofKey()));
        builder.clientSettings(clientBuilder.build());

        return builder.build();
    }

    /**
     * 解析客户端认证方式。兼容小写/带连字符的字符串。
     */
    static ClientAuthenticationMethod resolveClientAuthMethod(String raw) {
        if (raw == null) {
            return null;
        }
        String normalized = raw.trim().toLowerCase().replace('-', '_');
        return switch (normalized) {
            case "client_secret_basic" -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
            case "client_secret_post" -> ClientAuthenticationMethod.CLIENT_SECRET_POST;
            case "client_secret_jwt" -> ClientAuthenticationMethod.CLIENT_SECRET_JWT;
            case "private_key_jwt" -> ClientAuthenticationMethod.PRIVATE_KEY_JWT;
            case "none" -> ClientAuthenticationMethod.NONE;
            default -> {
                log.warn("Unknown client_auth_method: {} (allowed: client_secret_basic, "
                        + "client_secret_post, client_secret_jwt, private_key_jwt, none)", raw);
                yield null;
            }
        };
    }

    /**
     * 解析授权类型。常见值来自 RFC 6749 + Spring Authorization Server 扩展。
     */
    static AuthorizationGrantType resolveGrantType(String raw) {
        if (raw == null) {
            return null;
        }
        String normalized = raw.trim().toLowerCase().replace('-', '_');
        return switch (normalized) {
            case "authorization_code" -> AuthorizationGrantType.AUTHORIZATION_CODE;
            case "refresh_token" -> AuthorizationGrantType.REFRESH_TOKEN;
            case "client_credentials" -> AuthorizationGrantType.CLIENT_CREDENTIALS;
            case "password" -> new AuthorizationGrantType("password");
            case "jwt_bearer" -> new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:jwt-bearer");
            case "token_exchange" -> new AuthorizationGrantType(
                    "urn:ietf:params:oauth:grant-type:token-exchange");
            case "device_code" -> new AuthorizationGrantType(
                    "urn:ietf:params:oauth:grant-type:device_code");
            default -> {
                log.warn("Unknown grant_type: {} (allowed: authorization_code, refresh_token, "
                        + "client_credentials, password, jwt_bearer, token_exchange, device_code)", raw);
                yield null;
            }
        };
    }

    /**
     * 工具方法:逗号/分号/空白分隔的字符串 → 数组(便于解析 Nacos 配置字符串)。
     */
    static String[] splitCsv(String csv) {
        if (csv == null || csv.isBlank()) {
            return new String[0];
        }
        return Arrays.stream(csv.split("[,;\\s]+"))
                .filter(StringUtils::hasText)
                .toArray(String[]::new);
    }
}
