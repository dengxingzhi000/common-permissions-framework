package com.frog.auth.service;

import java.util.UUID;

/**
 * OAuth2 授权撤销服务接口
 *
 * <p>仅操作 {@code OAuth2AuthorizationService} 存储,不触碰 {@code JwtUtils}。
 * 单客户端撤销由调用方持有 access token 即可触发;全局撤销需上层授予
 * {@code oauth2:logout:global} 权限。</p>
 *
 * @since 2026-09-19
 */
public interface IOAuth2LogoutService {

    /**
     * 撤销指定 access token 对应的 OAuth2 授权(单客户端)
     *
     * @param accessToken  访问令牌
     * @param clientId     客户端 ID(仅用于审计日志)
     * @param callerUserId 调用者 userId(归属校验)
     * @throws com.frog.common.exception.BusinessException 4001 token 解析失败或不归属当前用户
     * @throws com.frog.common.exception.BusinessException 4004 OAuth2 授权未找到
     */
    void revokeByClient(String accessToken, String clientId, UUID callerUserId);

    /**
     * 撤销指定用户的所有 OAuth2 授权(全局,需 {@code oauth2:logout:global} 权限)
     *
     * @param targetUserId   目标用户 ID
     * @param reason         撤销原因
     * @param callerUsername 调用者用户名(审计)
     * @return 实际清理的授权条数
     */
    int revokeGlobal(UUID targetUserId, String reason, String callerUsername);
}