package com.auth.authservice.security;

import java.time.Duration;
import java.util.List;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;

@Service
public class RateLimitService {
    @NonNull
    private static final RedisScript<Long> INCREMENT_WITH_EXPIRY = new DefaultRedisScript<>("""
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return count
            """, Long.class);

    private final StringRedisTemplate redisTemplate;

    public RateLimitService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @SuppressWarnings("null") // Spring's @NonNull metadata is not type-use compatible with Eclipse JDT.
    public boolean isAllowed(String bucket, String clientAddress, int maxRequests, Duration window) {
        String key = "rate-limit:" + bucket + ":" + clientAddress;
        Long count = redisTemplate.execute(
                INCREMENT_WITH_EXPIRY,
                List.of(key),
                Long.toString(window.toSeconds()));
        return count != null && count <= maxRequests;
    }
}
