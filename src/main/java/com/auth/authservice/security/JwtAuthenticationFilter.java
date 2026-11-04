package com.auth.authservice.security;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import org.springframework.dao.DataAccessException;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth.authservice.service.JwtService;
import com.auth.authservice.service.TokenBlacklistService;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final TokenBlacklistService tokenBlacklistService;

    public JwtAuthenticationFilter(
            JwtService jwtService,
            TokenBlacklistService tokenBlacklistService) {
        this.jwtService = jwtService;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String path = request.getRequestURI()
                .substring(request.getContextPath().length());

        return path.startsWith("/internal/");
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = authHeader.substring(7);

        AuthPrincipal principal;

        try {
            // 1. Valida assinatura, issuer, expiração e claims.
            if (!jwtService.isTokenValid(jwt)) {
                unauthorized(response);
                return;
            }

            // 2. Verifica se o token foi revogado.
            if (tokenBlacklistService.isBlacklisted(jwt)) {
                unauthorized(response);
                return;
            }

            // 3. Extrai as informações do usuário.
            UUID userId = jwtService.extractUserId(jwt);
            UUID tenantId = jwtService.extractTenantId(jwt);
            String appKey = jwtService.extractAppKey(jwt);
            UUID sessionId = jwtService.extractSessionId(jwt);

            List<String> roles = jwtService.extractRoles(jwt);
            List<String> permissions = jwtService.extractPermissions(jwt);

            principal = new AuthPrincipal(userId, tenantId, appKey, sessionId);

            var authorities = Stream.concat(
                    roles.stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role)),
                    permissions.stream()
                            .map(SimpleGrantedAuthority::new))
                    .toList();

            var authentication = new UsernamePasswordAuthenticationToken(
                    principal,
                    null,
                    authorities);

            authentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JwtException | IllegalArgumentException exception) {
            SecurityContextHolder.clearContext();
            unauthorized(response);
            return;

        } catch (DataAccessException exception) {
            SecurityContextHolder.clearContext();

            response.sendError(
                    HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                    "Authentication service temporarily unavailable");
            return;
        }

        AuthContext.set(principal);

        try {
            filterChain.doFilter(request, response);
        } finally {
            AuthContext.clear();
            SecurityContextHolder.clearContext();
        }
    }

    private void unauthorized(HttpServletResponse response) throws IOException {
        SecurityContextHolder.clearContext();
        response.sendError(
                HttpServletResponse.SC_UNAUTHORIZED,
                "Invalid or expired token");
    }
}