package com.auth.authservice.security;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth.authservice.service.JwtService;
import com.auth.authservice.service.TokenBlacklistService;

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

        try {
            if (tokenBlacklistService.isBlacklisted(jwt) || !jwtService.isTokenValid(jwt)) {
                filterChain.doFilter(request, response);
                return;
            }

            UUID userId = jwtService.extractUserId(jwt);
            UUID tenantId = jwtService.extractTenantId(jwt);
            String appKey = jwtService.extractAppKey(jwt);

            List<String> roles = jwtService.extractRoles(jwt);
            List<String> permissions = jwtService.extractPermissions(jwt);

            AuthPrincipal principal = new AuthPrincipal(userId, tenantId, appKey);

            AuthContext.set(principal);

            if (SecurityContextHolder.getContext().getAuthentication() == null) {

                var authorities = permissions.stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList();

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                principal,
                                null,
                                authorities);

                authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            filterChain.doFilter(request, response);

        } catch (Exception exception) {
            SecurityContextHolder.clearContext();
            response.sendError(
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "Invalid or expired token");
        } finally {
            AuthContext.clear();
        }
    }
}