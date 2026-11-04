
package com.auth.authservice.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

@ExtendWith(MockitoExtension.class)
class TokenBlacklistServiceTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    private TokenBlacklistService tokenBlacklistService;

    @BeforeEach
    void setUp() {
        tokenBlacklistService = new TokenBlacklistService(redisTemplate);
    }

    @Test
    void shouldBlacklistToken() {
        String token = "valid.jwt.token";
        long expirationMillis = 60000;

        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        tokenBlacklistService.blacklistToken(token, expirationMillis);

        verify(valueOperations).set(
                startsWith("auth:blacklist:"),
                eq("blacklisted"),
                eq(Duration.ofMillis(expirationMillis))
        );
    }

    @Test
    void shouldReturnTrueWhenTokenIsBlacklisted() {
        String token = "valid.jwt.token";

        when(redisTemplate.hasKey(anyString())).thenReturn(true);

        boolean result = tokenBlacklistService.isBlacklisted(token);

        assertTrue(result);
        verify(redisTemplate).hasKey(startsWith("auth:blacklist:"));
    }

    @Test
    void shouldReturnFalseWhenTokenIsNotBlacklisted() {
        when(redisTemplate.hasKey(anyString())).thenReturn(false);

        boolean result = tokenBlacklistService.isBlacklisted("valid.jwt.token");

        assertFalse(result);
    }

    @Test
    void shouldReturnFalseWhenRedisReturnsNull() {
        when(redisTemplate.hasKey(anyString())).thenReturn(null);

        boolean result = tokenBlacklistService.isBlacklisted("valid.jwt.token");

        assertFalse(result);
    }

    @Test
    void shouldIgnoreNullOrBlankTokenWhenBlacklisting() {
        tokenBlacklistService.blacklistToken(null, 60000);
        tokenBlacklistService.blacklistToken("", 60000);
        tokenBlacklistService.blacklistToken("   ", 60000);

        verifyNoInteractions(redisTemplate);
    }

    @Test
    void shouldIgnoreInvalidExpiration() {
        tokenBlacklistService.blacklistToken("valid.jwt.token", 0);
        tokenBlacklistService.blacklistToken("valid.jwt.token", -1000);

        verifyNoInteractions(redisTemplate);
    }

    @Test
    void shouldReturnFalseForNullOrBlankToken() {
        assertFalse(tokenBlacklistService.isBlacklisted(null));
        assertFalse(tokenBlacklistService.isBlacklisted(""));
        assertFalse(tokenBlacklistService.isBlacklisted("   "));

        verifyNoInteractions(redisTemplate);
    }

    @Test
    void shouldPropagateRedisConnectionFailure() {
        when(redisTemplate.hasKey(anyString()))
                .thenThrow(new org.springframework.data.redis.RedisConnectionFailureException(
                        "Redis unavailable"
                ));

        assertThrows(
                org.springframework.data.redis.RedisConnectionFailureException.class,
                () -> tokenBlacklistService.isBlacklisted("valid.jwt.token")
        );
    }
}
