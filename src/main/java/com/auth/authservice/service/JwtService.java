package com.auth.authservice.service;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.auth.authservice.config.JwtProperties;
import com.auth.authservice.entity.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private final JwtProperties jwtProperties;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(User user) {
        var rolesList = user.getRoles();

        List<String> roles = rolesList
                .stream()
                .map(role -> role.getName())
                .toList();

        List<String> permissions = rolesList
                .stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(permission -> permission.getName())
                .distinct()
                .toList();

        return Jwts.builder()
                .setSubject(user.getEmail())
                .claim("tenantId", user.getTenantId().toString())
                .claim("roles", roles)
                .claim("permissions", permissions)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.getExpiration()))
                .signWith(getSignKey())
                .compact();
    }

    public String extractEmail(String token) {

        return extractAllClaims(token).getSubject();
    }

    public long getExpiration() {
        return jwtProperties.getExpiration();
    }

    public boolean isTokenValid(String token, UserDetails userDetails, UUID expectedTenantId) {

        if (userDetails == null || expectedTenantId == null) {
            return false;
        }

        Claims claims = extractAllClaims(token);

        String email = claims.getSubject();
        UUID tokenTenantId = extractTenantId(token);
        Date expiration = claims.getExpiration();

        return email != null
                && email.equals(userDetails.getUsername())
                && tokenTenantId.equals(expectedTenantId)
                && expiration != null
                && expiration.after(new Date());
    }

    private Claims extractAllClaims(String token) {

        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public long getRemainingTime(String token) {

        Date expiration = extractAllClaims(token).getExpiration();

        return expiration.getTime() - System.currentTimeMillis();
    }

    public UUID extractTenantId(String token) {
        String tenantId = extractClaim(
                token,
                claims -> claims.get("tenantId", String.class));

        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("JWT tenantId claim is missing");
        }

        try {
            return UUID.fromString(tenantId);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("JWT tenantId claim is invalid", e);
        }
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
}
