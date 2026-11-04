package com.auth.authservice.security;

import java.util.UUID;

public record AuthPrincipal(
        UUID userId,
        UUID tenantId,
        String appKey,
        UUID sessionId
) {
}