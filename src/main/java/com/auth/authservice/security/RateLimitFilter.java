package com.auth.authservice.security;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth.authservice.exception.ApiError;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class RateLimitFilter extends OncePerRequestFilter {
    private static final Limit LOGIN_LIMIT = new Limit("login", 5, Duration.ofMinutes(1));
    private static final Limit REFRESH_LIMIT = new Limit("refresh", 10, Duration.ofMinutes(1));
    private static final Limit TENANT_CREATION_LIMIT = new Limit("tenant-creation", 3, Duration.ofHours(1));
    private static final Limit MEMBERSHIP_REQUEST_LIMIT = new Limit("membership-request", 3, Duration.ofHours(1));

    private final RateLimitService rateLimitService;
    private final ObjectMapper objectMapper;

    public RateLimitFilter(RateLimitService rateLimitService, ObjectMapper objectMapper) {
        this.rateLimitService = rateLimitService;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        Limit limit = resolveLimit(request);
        if (limit == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            if (!rateLimitService.isAllowed(limit.bucket(), request.getRemoteAddr(), limit.maxRequests(), limit.window())) {
                response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(limit.window().toSeconds()));
                writeError(request, response, 429,
                        "Too Many Requests", "Too many requests. Try again later");
                return;
            }
        } catch (RedisConnectionFailureException exception) {
            writeError(request, response, HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                    "Service Unavailable", "Rate limiting service is temporarily unavailable");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private Limit resolveLimit(HttpServletRequest request) {
        if (!"POST".equals(request.getMethod())) {
            return null;
        }

        String path = request.getRequestURI().substring(request.getContextPath().length());
        return switch (path) {
            case "/auth/login" -> LOGIN_LIMIT;
            case "/auth/refresh" -> REFRESH_LIMIT;
            case "/admin/tenants" -> TENANT_CREATION_LIMIT;
            case "/auth/membership-requests" -> MEMBERSHIP_REQUEST_LIMIT;
            default -> null;
        };
    }

    private void writeError(HttpServletRequest request, HttpServletResponse response, int status,
            String error, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getWriter(), new ApiError(
                Instant.now(), status, error, message, request.getRequestURI(), Map.of()));
    }

    private record Limit(String bucket, int maxRequests, Duration window) {
    }
}
