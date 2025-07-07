package com.dcode.Security.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;


public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private String token;

    public JwtAuthenticationToken(String token) {
        super(null);
        this.token = token;
        setAuthenticated(false);
    }

    public String getToken() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }
}
