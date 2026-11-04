package com.auth.authservice.security;

import java.io.IOException;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth.authservice.service.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class ClientJwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    public ClientJwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String path = request.getRequestURI()
                .substring(request.getContextPath().length());

        return !path.startsWith("/internal/");
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            unauthorized(response);
            return;
        }

        String token = authHeader.substring(7);

        ClientPrincipal principal;

        try {
            if (!jwtService.isClientTokenValid(token)) {
                unauthorized(response);
                return;
            }

            String clientId = jwtService.extractClientId(token);
            String appKey = jwtService.extractClientAppKey(token);

            principal = new ClientPrincipal(clientId, appKey);

        } catch (RuntimeException exception) {
            unauthorized(response);
            return;
        }

        var authentication = new UsernamePasswordAuthenticationToken(
                principal,
                null,
                java.util.List.of(
                        new SimpleGrantedAuthority("ROLE_APPLICATION_CLIENT")));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        try {
            filterChain.doFilter(request, response);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private void unauthorized(HttpServletResponse response) throws IOException {
        SecurityContextHolder.clearContext();

        response.sendError(
                HttpServletResponse.SC_UNAUTHORIZED,
                "Invalid or expired client token");
    }
}