package com.auth.authservice.service;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.auth.authservice.config.JwtProperties;
import com.auth.authservice.entity.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtService {
    private final JwtProperties jwtProperties;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public String generateToken(User user) {
        var rolesList = user.getRoles();
        List<String> roles = rolesList.stream().map(role -> role.getName()).toList();
        List<String> permissions = rolesList.stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(permission -> permission.getName())
                .distinct()
                .toList();

        return Jwts.builder()
                .setHeaderParam("kid", jwtProperties.getKeyId())
                .setIssuer(jwtProperties.getIssuer())
                .setAudience(jwtProperties.getAudience())
                .setSubject(user.getEmail())
                .setId(UUID.randomUUID().toString())
                .claim("tenantId", user.getTenantId().toString())
                .claim("roles", roles)
                .claim("permissions", permissions)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.getExpiration()))
                .signWith(signingKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public String extractEmail(String token) { return extractAllClaims(token).getSubject(); }
    public long getExpiration() { return jwtProperties.getExpiration(); }

    public boolean isTokenValid(String token, UserDetails userDetails, UUID expectedTenantId) {
        if (userDetails == null || expectedTenantId == null) return false;
        Claims claims = extractAllClaims(token);
        String email = claims.getSubject();
        UUID tokenTenantId = extractTenantId(token);
        Date expiration = claims.getExpiration();
        return email != null
                && email.equals(userDetails.getUsername())
                && tokenTenantId.equals(expectedTenantId)
                && claims.getId() != null
                && !claims.getId().isBlank()
                && userDetails.isEnabled()
                && userDetails.isAccountNonExpired()
                && userDetails.isAccountNonLocked()
                && userDetails.isCredentialsNonExpired()
                && expiration != null
                && expiration.after(new Date());
    }

    public Map<String, Object> getJwkSet() {
        RSAPublicKey publicKey = (RSAPublicKey) jwtProperties.getPublicKey();
        return Map.of("keys", List.of(Map.of(
                "kty", "RSA", "use", "sig", "alg", "RS256", "kid", jwtProperties.getKeyId(),
                "n", base64Url(publicKey.getModulus()), "e", base64Url(publicKey.getPublicExponent()))));
    }

    private PrivateKey signingKey() { return jwtProperties.getPrivateKey(); }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .requireIssuer(jwtProperties.getIssuer())
                .requireAudience(jwtProperties.getAudience())
                .setSigningKey(jwtProperties.getPublicKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public long getRemainingTime(String token) {
        return extractAllClaims(token).getExpiration().getTime() - System.currentTimeMillis();
    }

    public UUID extractTenantId(String token) {
        String tenantId = extractClaim(token, claims -> claims.get("tenantId", String.class));
        if (tenantId == null || tenantId.isBlank()) throw new IllegalArgumentException("JWT tenantId claim is missing");
        try {
            return UUID.fromString(tenantId);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("JWT tenantId claim is invalid", e);
        }
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(extractAllClaims(token));
    }

    private String base64Url(BigInteger value) {
        byte[] bytes = value.toByteArray();
        int start = bytes.length > 1 && bytes[0] == 0 ? 1 : 0;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOfRange(bytes, start, bytes.length));
    }
}
