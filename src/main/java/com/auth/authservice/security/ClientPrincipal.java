package com.auth.authservice.security;

public record ClientPrincipal(
        String clientId,
        String appKey
) {
}
