package com.auth.authservice.service;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;

import org.springframework.stereotype.Service;

import com.auth.authservice.config.JwtProperties;
import com.auth.authservice.entity.ApplicationClient;
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

    public String generateToken(MembershipApplication membershipApplication, UUID sessionId) {

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

        Objects.requireNonNull(sessionId, "sessionId cannot be null");

        return Jwts.builder()
                .setSubject(user.getId().toString())
                .setIssuer(ISSUER)
                .setAudience(application.getAppKey())
                .claim("tenantId", tenant.getId().toString())
                .claim("appKey", application.getAppKey())
                .claim("sessionId", sessionId.toString())
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

            String subject = claims.getSubject();
            String tenantId = claims.get("tenantId", String.class);
            String sessionId = claims.get("sessionId", String.class);
            String appKey = claims.get("appKey", String.class);
            String audience = claims.getAudience();

            return isValidUuid(subject)
                    && isValidUuid(tenantId)
                    && isValidUuid(sessionId)
                    && appKey != null
                    && !appKey.isBlank()
                    && appKey.equals(audience)
                    && !extractStringList(claims, "roles").isEmpty();

        } catch (Exception exception) {
            return false;
        }
    }

    public boolean isTokenValid(String token, String expectedAppKey) {
        if (expectedAppKey == null || expectedAppKey.isBlank()) {
            return false;
        }

        try {
            Claims claims = extractAllClaims(token);

            return isTokenValid(token)
                    && expectedAppKey.equals(claims.get("appKey", String.class))
                    && expectedAppKey.equals(claims.getAudience());

        } catch (Exception exception) {
            return false;
        }
    }

    public UUID extractSessionId(String token) {
        return UUID.fromString(
                extractAllClaims(token).get("sessionId", String.class));
    }

    public long getExpiration() {
        return jwtProperties.getExpiration();
    }

    public long getClientExpiration() {
        return jwtProperties.getClientExpiration();
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

    private boolean isValidUuid(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }

        try {
            UUID.fromString(value);
            return true;
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private Key getClientSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getClientSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateClientToken(ApplicationClient client) {

        String appKey = client.getApplication().getAppKey();

        Date now = new Date();

        return Jwts.builder()
                .setSubject(client.getClientId())
                .setIssuer(ISSUER)
                .setAudience(ISSUER)
                .claim("token_type", "client")
                .claim("appKey", appKey)
                .setIssuedAt(now)
                .setExpiration(new Date(
                        now.getTime() + jwtProperties.getClientExpiration()))
                .signWith(getClientSignKey())
                .compact();
    }

    public boolean isClientTokenValid(String token) {
        try {
            Claims claims = extractClientAllClaims(token);

            String subject = claims.getSubject();
            String appKey = claims.get("appKey", String.class);
            String tokenType = claims.get("token_type", String.class);

            return subject != null
                    && !subject.isBlank()
                    && appKey != null
                    && !appKey.isBlank()
                    && ISSUER.equals(claims.getAudience())
                    && "client".equals(tokenType);

        } catch (Exception exception) {
            return false;
        }
    }

    public String extractClientId(String token) {
        return extractClientAllClaims(token).getSubject();
    }

    public String extractClientAppKey(String token) {
        return extractClientAllClaims(token).get("appKey", String.class);
    }

    private Claims extractClientAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getClientSignKey())
                .requireIssuer(ISSUER)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

}