package com.frog.auth.security;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

/**
 * Side-indexing decorator — stub created in Task 3, fully implemented in Task 5.
 */
public class SideIndexingOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final OAuth2AuthorizationService delegate;

    public SideIndexingOAuth2AuthorizationService(OAuth2AuthorizationService delegate) {
        this.delegate = delegate;
    }

    @Override public void save(OAuth2Authorization authorization) { delegate.save(authorization); }
    @Override public void remove(OAuth2Authorization authorization) { delegate.remove(authorization); }
    @Override public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) { return delegate.findByToken(token, tokenType); }
    @Override public OAuth2Authorization findById(String id) { return delegate.findById(id); }
}