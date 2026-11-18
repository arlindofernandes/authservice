package com.auth.authservice.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.auth.authservice.service.JwtService;
import com.auth.authservice.service.TokenBlacklistService;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;

class JwtAuthenticationFilterTest {

    private JwtService jwtService;
    private UserDetailsService userDetailsService;
    private TokenBlacklistService tokenBlacklistService;
    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        jwtService = mock(JwtService.class);
        userDetailsService = mock(UserDetailsService.class);
        tokenBlacklistService = mock(TokenBlacklistService.class);

        filter = new JwtAuthenticationFilter(
                jwtService,
                userDetailsService,
                tokenBlacklistService, new ObjectMapper().findAndRegisterModules());
    }

    @AfterEach
    void clearTenantContext() {
        TenantContext.clear();
    }

    @Test
    void shouldReturnUnauthorizedWhenJwtIsMalformed() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/admin");
        request.addHeader("Authorization", "Bearer invalid-token");

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        when(tokenBlacklistService.isBlacklisted("invalid-token"))
                .thenReturn(false);

        when(jwtService.extractEmail("invalid-token"))
                .thenThrow(new IllegalArgumentException("Invalid JWT"));

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(401);
        verifyNoInteractions(userDetailsService);
        verifyNoInteractions(filterChain);
        assertThat(TenantContext.get()).isNull();
    }

    @Test
    void shouldClearTenantContextAfterRequest() throws Exception {
        UUID tenantId = UUID.randomUUID();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer invalid-token");

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        when(tokenBlacklistService.isBlacklisted("invalid-token"))
                .thenReturn(false);

        when(jwtService.extractEmail("invalid-token"))
                .thenThrow(new IllegalArgumentException("Invalid JWT"));

        TenantContext.set(tenantId);

        filter.doFilter(request, response, filterChain);

        assertThat(TenantContext.get()).isNull();
    }

    @Test
    void shouldReturnServiceUnavailableWhenRedisIsDown() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/admin");
        request.addHeader("Authorization", "Bearer valid-token");

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        when(tokenBlacklistService.isBlacklisted("valid-token"))
                .thenThrow(new RedisConnectionFailureException("Redis unavailable"));

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(503);

        verifyNoInteractions(jwtService);
        verifyNoInteractions(userDetailsService);
        verifyNoInteractions(filterChain);

    }

    @Test
    void shouldReturnUnauthorizedWhenJwtIsInvalid() throws Exception {
        String jwt = "valid-format-token";
        String email = "user@example.com";
        UUID tenantId = UUID.randomUUID();

        UserDetails userDetails = User.withUsername(email)
                .password("password")
                .authorities("ROLE_USER")
                .build();

        when(tokenBlacklistService.isBlacklisted(jwt)).thenReturn(false);
        when(jwtService.extractEmail(jwt)).thenReturn(email);
        when(jwtService.extractTenantId(jwt)).thenReturn(tenantId);
        when(userDetailsService.loadUserByUsername(email)).thenReturn(userDetails);
        when(jwtService.isTokenValid(jwt, userDetails, tenantId)).thenReturn(false);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + jwt);

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = mock(FilterChain.class);

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void shouldReturnUnauthorizedWhenJwtUserNoLongerExists() throws Exception {
        String jwt = "valid-format-token";
        String email = "deleted@example.com";
        UUID tenantId = UUID.randomUUID();

        when(tokenBlacklistService.isBlacklisted(jwt)).thenReturn(false);
        when(jwtService.extractEmail(jwt)).thenReturn(email);
        when(jwtService.extractTenantId(jwt)).thenReturn(tenantId);
        when(userDetailsService.loadUserByUsername(email))
                .thenThrow(new UsernameNotFoundException("User not found"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + jwt);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        verify(filterChain, never()).doFilter(request, response);
        assertThat(TenantContext.get()).isNull();
    }
}
