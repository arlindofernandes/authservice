package com.auth.authservice.service;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

import org.springframework.stereotype.Service;

import com.auth.authservice.config.JwtProperties;
import com.auth.authservice.entity.MembershipApplication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private static final String ISSUER = "authservice";

    private final JwtProperties jwtProperties;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(MembershipApplication membershipApplication) {

        var user = membershipApplication.getMembership().getUser();
        var tenant = membershipApplication.getMembership().getTenant();
        var application = membershipApplication.getApplication();

        List<String> roles = membershipApplication.getMembershipApplicationRoles()
                .stream()
                .map(membershipRole -> membershipRole.getRole())
                .map(role -> role.getName())
                .distinct()
                .toList();

        List<String> permissions = membershipApplication.getMembershipApplicationRoles()
                .stream()
                .map(membershipRole -> membershipRole.getRole())
                .flatMap(role -> role.getRolePermissions().stream())
                .map(rolePermission -> rolePermission.getPermission())
                .map(permission -> permission.getName())
                .distinct()
                .toList();

        return Jwts.builder()
                .setSubject(user.getId().toString())
                .setIssuer(ISSUER)
                .setAudience(application.getAppKey())
                .claim("tenantId", tenant.getId().toString())
                .claim("appKey", application.getAppKey())
                .claim("roles", roles)
                .claim("permissions", permissions)
                .setIssuedAt(new Date())
                .setExpiration(new Date(
                        System.currentTimeMillis() + jwtProperties.getExpiration()))
                .signWith(getSignKey())
                .compact();
    }

    public UUID extractUserId(String token) {
        return UUID.fromString(extractAllClaims(token).getSubject());
    }

    public UUID extractTenantId(String token) {
        return UUID.fromString(
                extractAllClaims(token).get("tenantId", String.class));
    }

    public String extractAppKey(String token) {
        return extractAllClaims(token).get("appKey", String.class);
    }

    public List<String> extractRoles(String token) {
        return extractStringList(extractAllClaims(token), "roles");
    }

    public List<String> extractPermissions(String token) {
        return extractStringList(extractAllClaims(token), "permissions");
    }

   public boolean isTokenValid(String token) {
    try {
        Claims claims = extractAllClaims(token);

        String appKey = claims.get("appKey", String.class);
        String audience = claims.getAudience();

        return claims.getSubject() != null
                && claims.getExpiration() != null
                && claims.getExpiration().after(new Date())
                && claims.get("tenantId", String.class) != null
                && appKey != null
                && !appKey.isBlank()
                && appKey.equals(audience);

    } catch (Exception exception) {
        return false;
    }
}

    public long getExpiration() {
        return jwtProperties.getExpiration();
    }

    public long getRemainingTime(String token) {
        Date expiration = extractAllClaims(token).getExpiration();
        return expiration.getTime() - System.currentTimeMillis();
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .requireIssuer(ISSUER)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(extractAllClaims(token));
    }

    private List<String> extractStringList(Claims claims, String claimName) {

        Object value = claims.get(claimName);

        if (!(value instanceof List<?> list)) {
            throw new IllegalArgumentException(
                    "Invalid JWT claim: " + claimName);
        }

        return list.stream()
                .map(item -> {
                    if (!(item instanceof String string)) {
                        throw new IllegalArgumentException(
                                "Invalid value in JWT claim: " + claimName);
                    }
                    return string;
                })
                .toList();
    }
}