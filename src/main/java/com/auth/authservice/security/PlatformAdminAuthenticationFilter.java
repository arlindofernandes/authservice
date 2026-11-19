package com.auth.authservice.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth.authservice.config.AdminRegistrationProperties;
import com.auth.authservice.exception.ApiError;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class PlatformAdminAuthenticationFilter extends OncePerRequestFilter {
    static final String ADMIN_TOKEN_HEADER = "X-Admin-Token";
    private static final String ADMIN_TENANTS_PATH = "/admin/tenants";
    private static final String PROMETHEUS_PATH = "/actuator/prometheus";

    private final AdminRegistrationProperties properties;
    private final ObjectMapper objectMapper;

    public PlatformAdminAuthenticationFilter(AdminRegistrationProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        boolean createsTenant = "POST".equals(request.getMethod()) && ADMIN_TENANTS_PATH.equals(request.getRequestURI());
        boolean readsMetrics = "GET".equals(request.getMethod()) && PROMETHEUS_PATH.equals(request.getRequestURI());
        return !createsTenant && !readsMetrics;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        String suppliedToken = request.getHeader(ADMIN_TOKEN_HEADER);
        if (suppliedToken == null || !MessageDigest.isEqual(
                properties.getToken().getBytes(StandardCharsets.UTF_8),
                suppliedToken.getBytes(StandardCharsets.UTF_8))) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "AdminToken");
            response.setContentType("application/json");
            objectMapper.writeValue(response.getWriter(), new ApiError(
                    Instant.now(), HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized",
                    "A valid platform administrator token is required", request.getRequestURI(), Map.of()));
            return;
        }

        var authentication = new UsernamePasswordAuthenticationToken(
                "platform-admin", null, List.of(new SimpleGrantedAuthority("ROLE_PLATFORM_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }
}
