package com.auth.authservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;

import com.auth.authservice.config.JwtProperties;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

class JwtServiceTest {
    private JwtService jwtService;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        JwtProperties properties = new JwtProperties();
        properties.setPrivateKey(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        properties.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        properties.setIssuer("auth-service-test");
        properties.setAudience("test-clients");
        properties.setKeyId("test-key-1");
        properties.setExpiration(3600000);
        jwtService = new JwtService(properties);
    }

    @Test
    void shouldExtractTenantIdFromValidToken() {
        UUID tenantId = UUID.randomUUID();
        assertThat(jwtService.extractTenantId(token("user@example.com", tenantId.toString(), true, true)))
                .isEqualTo(tenantId);
    }

    @Test
    void shouldThrowExceptionWhenTenantIdIsMissing() {
        assertThatThrownBy(() -> jwtService.extractTenantId(token("user@example.com", null, true, true)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("JWT tenantId claim is missing");
    }

    @Test
    void shouldThrowExceptionWhenTenantIdIsInvalid() {
        assertThatThrownBy(() -> jwtService.extractTenantId(token("user@example.com", "invalid-uuid", true, true)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("JWT tenantId claim is invalid");
    }

    @Test
    void shouldRejectTokenWithoutExpiration() {
        UUID tenantId = UUID.randomUUID();
        assertThat(jwtService.isTokenValid(token("user@example.com", tenantId.toString(), false, true), user(), tenantId))
                .isFalse();
    }

    @Test
    void shouldRejectTokenWithoutSubject() {
        UUID tenantId = UUID.randomUUID();
        assertThat(jwtService.isTokenValid(token(null, tenantId.toString(), true, true), user(), tenantId)).isFalse();
    }

    @Test
    void shouldRejectTokenWhenTenantIdDoesNotMatch() {
        assertThat(jwtService.isTokenValid(token("user@example.com", UUID.randomUUID().toString(), true, true), user(), UUID.randomUUID()))
                .isFalse();
    }

    @Test
    void shouldRejectTokenForDisabledUser() {
        UUID tenantId = UUID.randomUUID();
        var disabledUser = User.withUsername("user@example.com").password("password").authorities("ROLE_USER").disabled(true).build();
        assertThat(jwtService.isTokenValid(token("user@example.com", tenantId.toString(), true, true), disabledUser, tenantId)).isFalse();
    }

    private String token(String subject, String tenantId, boolean withExpiration, boolean withId) {
        var builder = Jwts.builder()
                .setHeaderParam("kid", "test-key-1")
                .setIssuer("auth-service-test")
                .setAudience("test-clients")
                .setIssuedAt(new Date());
        if (subject != null) builder.setSubject(subject);
        if (tenantId != null) builder.claim("tenantId", tenantId);
        if (withId) builder.setId(UUID.randomUUID().toString());
        if (withExpiration) builder.setExpiration(new Date(System.currentTimeMillis() + 3600000));
        return builder.signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256).compact();
    }

    private org.springframework.security.core.userdetails.UserDetails user() {
        return User.withUsername("user@example.com").password("password").authorities("ROLE_USER").build();
    }
}
