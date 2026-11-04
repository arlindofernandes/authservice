package com.auth.authservice.dto;

public record ClientTokenResponse(
        String accessToken,
        String tokenType,
        long expiresIn
) {
}