package com.auth.authservice.service;

import java.time.Duration;
import java.util.Objects;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class TokenBlacklistService {
    private final StringRedisTemplate redisTemplate;

    public TokenBlacklistService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void blacklistToken(String token, long expirationMillis) {
        if (token == null || token.isBlank() || expirationMillis <= 0) {
            return;
        }
        Duration duration = Objects.requireNonNull(
                Duration.ofMillis(expirationMillis));

        redisTemplate.opsForValue().set(
                token,
                "blacklisted",
                duration);
    }

    public boolean isBlacklisted(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }

        Boolean exists = redisTemplate.hasKey(token);

        return exists != null && exists;
    }
}
