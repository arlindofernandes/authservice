
package com.auth.authservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.auth.authservice.config.JwtProperties;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

class JwtServiceTest {

        private JwtService jwtService;
        private String secret;

        @BeforeEach
        void setUp() {
                JwtProperties properties = new JwtProperties();

                secret = Base64.getEncoder().encodeToString(new byte[32]);

                properties.setSecret(secret);
                properties.setExpiration(3600000);

                jwtService = new JwtService(properties);
        }

        @Test
        void shouldExtractTenantIdFromValidToken() {
                UUID tenantId = UUID.randomUUID();

                String token = Jwts.builder()
                                .setSubject("user@example.com")
                                .claim("tenantId", tenantId.toString())
                                .setIssuedAt(new Date())
                                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                                .signWith(
                                                Keys.hmacShaKeyFor(
                                                                Base64.getDecoder().decode(secret)))
                                .compact();

                assertThat(jwtService.extractTenantId(token))
                                .isEqualTo(tenantId);
        }

        @Test
        void shouldThrowExceptionWhenTenantIdIsMissing() {
                String token = Jwts.builder()
                                .setSubject("user@example.com")
                                .setIssuedAt(new Date())
                                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                                .signWith(
                                                Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret)))
                                .compact();

                assertThatThrownBy(() -> jwtService.extractTenantId(token))
                                .isInstanceOf(IllegalArgumentException.class)
                                .hasMessage("JWT tenantId claim is missing");
        }

        @Test
        void shouldThrowExceptionWhenTenantIdIsInvalid() {
                String token = Jwts.builder()
                                .setSubject("user@example.com")
                                .claim("tenantId", "invalid-uuid")
                                .setIssuedAt(new Date())
                                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                                .signWith(
                                                Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret)))
                                .compact();

                assertThatThrownBy(() -> jwtService.extractTenantId(token))
                                .isInstanceOf(IllegalArgumentException.class)
                                .hasMessage("JWT tenantId claim is invalid");
        }

        @Test
        void shouldRejectTokenWithoutExpiration() {
                UUID tenantId = UUID.randomUUID();

                String token = Jwts.builder()
                                .setSubject("user@example.com")
                                .claim("tenantId", tenantId.toString())
                                .setIssuedAt(new Date())
                                .signWith(
                                                Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret)))
                                .compact();

                assertThat(jwtService.isTokenValid(
                                token,
                                org.springframework.security.core.userdetails.User
                                                .withUsername("user@example.com")
                                                .password("password")
                                                .authorities("ROLE_USER")
                                                .build(),
                                tenantId))
                                .isFalse();
        }

        @Test
        void shouldRejectTokenWithoutSubject() {
                UUID tenantId = UUID.randomUUID();

                String token = Jwts.builder()
                                .claim("tenantId", UUID.randomUUID().toString())
                                .setIssuedAt(new Date())
                                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                                .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret)))
                                .compact();

                var userDetails = org.springframework.security.core.userdetails.User
                                .withUsername("user@example.com")
                                .password("password")
                                .authorities("ROLE_USER")
                                .build();

                assertThat(jwtService.isTokenValid(token, userDetails, tenantId)).isFalse();
        }

        @Test
        void shouldRejectTokenWhenTenantIdDoesNotMatch() {
                UUID tokenTenantId = UUID.randomUUID();
                UUID expectedTenantId = UUID.randomUUID();

                String token = Jwts.builder()
                                .setSubject("user@example.com")
                                .claim("tenantId", tokenTenantId.toString())
                                .setIssuedAt(new Date())
                                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                                .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret)))
                                .compact();

                var userDetails = org.springframework.security.core.userdetails.User
                                .withUsername("user@example.com")
                                .password("password")
                                .authorities("ROLE_USER")
                                .build();

                assertThat(jwtService.isTokenValid(token, userDetails, expectedTenantId))
                                .isFalse();
        }
}
