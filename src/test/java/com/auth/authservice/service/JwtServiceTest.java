
package com.auth.authservice.service;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.auth.authservice.config.JwtProperties;
import com.auth.authservice.entity.*;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

class JwtServiceTest {

    private static final String USER_SECRET = Base64.getEncoder()
            .encodeToString(new byte[64]);

    private static final byte[] CLIENT_KEY_BYTES = new byte[64];

    static {
        java.util.Arrays.fill(CLIENT_KEY_BYTES, (byte) 1);
    }

    private static final String CLIENT_SECRET = Base64.getEncoder()
            .encodeToString(CLIENT_KEY_BYTES);

    private JwtService jwtService;

    private MembershipApplication membershipApplication;

    private UUID userId;
    private UUID tenantId;
    private UUID membershipApplicationId;
    private UUID sessionId;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret(USER_SECRET);
        properties.setExpiration(900000);
        properties.setClientSecret(CLIENT_SECRET);
        properties.setClientExpiration(300000);

        jwtService = new JwtService(properties);
        sessionId = UUID.randomUUID();
        userId = UUID.randomUUID();
        tenantId = UUID.randomUUID();
        membershipApplicationId = UUID.randomUUID();

        User user = new User();
        user.setId(userId);
        user.setName("Test User");
        user.setEmail("test@example.com");

        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setName("Test Tenant");
        tenant.setSlug("test-tenant");

        TenantMembership membership = new TenantMembership();
        membership.setUser(user);
        membership.setTenant(tenant);

        Application application = new Application();
        application.setId(UUID.randomUUID());
        application.setAppKey("test-app");
        application.setName("CardWise");

        Permission permission = new Permission();
        permission.setId(UUID.randomUUID());
        permission.setName("USER_READ");
        permission.setApplication(application);

        Role role = new Role();
        role.setId(UUID.randomUUID());
        role.setName("USER");
        role.setApplication(application);

        RolePermission rolePermission = new RolePermission();
        RolePermissionId rolePermissionId = new RolePermissionId();
        rolePermissionId.setRoleId(role.getId());
        rolePermissionId.setPermissionId(permission.getId());

        rolePermission.setId(rolePermissionId);
        rolePermission.setRole(role);
        rolePermission.setPermission(permission);

        role.setRolePermissions(Set.of(rolePermission));

        MembershipApplication membershipApp = new MembershipApplication();
        membershipApp.setId(membershipApplicationId);
        membershipApp.setMembership(membership);
        membershipApp.setApplication(application);

        MembershipApplicationRole membershipRole = new MembershipApplicationRole();

        MembershipApplicationRoleId membershipRoleId = new MembershipApplicationRoleId();

        membershipRoleId.setMembershipApplicationId(membershipApplicationId);
        membershipRoleId.setRoleId(role.getId());

        membershipRole.setId(membershipRoleId);
        membershipRole.setMembershipApplication(membershipApp);
        membershipRole.setRole(role);

        membershipApp.setMembershipApplicationRoles(
                new HashSet<>(Set.of(membershipRole)));

        membershipApplication = membershipApp;
    }

    @Test
    void shouldGenerateValidToken() {
        String token = jwtService.generateToken(membershipApplication, sessionId);

        assertNotNull(token);
        assertTrue(jwtService.isTokenValid(token));

        assertEquals(userId, jwtService.extractUserId(token));
        assertEquals(tenantId, jwtService.extractTenantId(token));
        assertEquals(sessionId, jwtService.extractSessionId(token));
        assertEquals("test-app", jwtService.extractAppKey(token));

        assertEquals(
                Set.of("USER"),
                Set.copyOf(jwtService.extractRoles(token)));

        assertEquals(
                Set.of("USER_READ"),
                Set.copyOf(jwtService.extractPermissions(token)));
    }

    @Test
    void shouldGenerateDifferentSessionIdsForDifferentSessions() {
        UUID anotherSessionId = UUID.randomUUID();

        String firstToken = jwtService.generateToken(
                membershipApplication,
                sessionId);

        String secondToken = jwtService.generateToken(
                membershipApplication,
                anotherSessionId);

        assertNotEquals(
                jwtService.extractSessionId(firstToken),
                jwtService.extractSessionId(secondToken));
    }

    @Test
    void shouldRejectExpiredToken() {
        String token = createToken(
                USER_SECRET,
                "authservice",
                "test-app",
                tenantId.toString(),
                new Date(System.currentTimeMillis() - 10000));

        assertFalse(jwtService.isTokenValid(token));
    }

    @Test
    void shouldRejectTokenWithInvalidSignature() {
        byte[] anotherKey = new byte[64];
        java.util.Arrays.fill(anotherKey, (byte) 1);

        String anotherSecret = Base64.getEncoder()
                .encodeToString(anotherKey);

        String token = createToken(
                anotherSecret,
                "authservice",
                "test-app",
                tenantId.toString(),
                new Date(System.currentTimeMillis() + 60000));

        assertFalse(jwtService.isTokenValid(token));
    }

    @Test
    void shouldRejectTokenWithWrongIssuer() {
        String token = createToken(
                USER_SECRET,
                "another-issuer",
                "test-app",
                tenantId.toString(),
                new Date(System.currentTimeMillis() + 60000));

        assertFalse(jwtService.isTokenValid(token));
    }

    @Test
    void shouldRejectTokenWithInvalidTenantId() {
        String token = createToken(
                USER_SECRET,
                "authservice",
                "test-app",
                "invalid-uuid",
                new Date(System.currentTimeMillis() + 60000));

        assertFalse(jwtService.isTokenValid(token));
    }

    private String createToken(
            String secret,
            String issuer,
            String appKey,
            String tenantId,
            Date expiration) {

        return Jwts.builder()
                .setSubject(UUID.randomUUID().toString())
                .setIssuer(issuer)
                .setAudience(appKey)
                .claim("appKey", appKey)
                .claim("tenantId", tenantId)
                .claim("roles", Set.of("USER"))
                .claim("permissions", Set.of("USER_READ"))
                .setIssuedAt(new Date())
                .setExpiration(expiration)
                .signWith(
                        Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret)),
                        SignatureAlgorithm.HS512)
                .compact();
    }

    @Test
    void shouldRejectTokenWithInvalidRoles() {
        String token = createMalformedToken("roles", "INVALID");

        assertThrows(
                IllegalArgumentException.class,
                () -> jwtService.extractRoles(token));
    }

    @Test
    void shouldRejectTokenWithInvalidPermissions() {
        String token = createMalformedToken("permissions", "INVALID");

        assertThrows(
                IllegalArgumentException.class,
                () -> jwtService.extractPermissions(token));
    }

    private String createMalformedToken(String claimName, Object value) {
        return Jwts.builder()
                .setSubject(UUID.randomUUID().toString())
                .setIssuer("authservice")
                .setAudience("test-app")
                .claim("appKey", "test-app")
                .claim("tenantId", tenantId.toString())
                .claim("roles", Set.of("USER"))
                .claim("permissions", Set.of("USER_READ"))
                .claim(claimName, value)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(
                        Keys.hmacShaKeyFor(Base64.getDecoder().decode(USER_SECRET)),
                        SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    void shouldRejectTokenWithInvalidRolesStructure() {
        String token = createMalformedToken("roles", "ADMIN");

        assertFalse(jwtService.isTokenValid(token));
    }

    @Test
    void shouldRejectTokenWithInvalidPermissionsStructure() {
        String token = createMalformedToken("permissions", 123);

        assertFalse(jwtService.isTokenValid(token));
    }

    @Test
    void shouldRejectTokenWithInvalidUserId() {
        String token = Jwts.builder()
                .setSubject("invalid-uuid")
                .setIssuer("authservice")
                .setAudience("test-app")
                .claim("appKey", "test-app")
                .claim("tenantId", tenantId.toString())
                .claim("roles", Set.of("USER"))
                .claim("permissions", Set.of("USER_READ"))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(
                        Keys.hmacShaKeyFor(Base64.getDecoder().decode(USER_SECRET)),
                        SignatureAlgorithm.HS256)
                .compact();

        assertFalse(jwtService.isTokenValid(token));
    }

    @Test
    void shouldAcceptTokenWithExpectedAudience() {
        String token = jwtService.generateToken(membershipApplication, sessionId);

        assertTrue(jwtService.isTokenValid(token, "test-app"));
    }

    @Test
    void shouldRejectTokenWithDifferentExpectedAudience() {
        String token = jwtService.generateToken(membershipApplication, sessionId);

        assertFalse(jwtService.isTokenValid(token, "another-app"));
    }

    @Test
    void shouldRejectTokenWhenExpectedAudienceIsBlank() {
        String token = jwtService.generateToken(membershipApplication, sessionId);

        assertFalse(jwtService.isTokenValid(token, ""));
    }

    @Test
    void shouldGenerateValidClientToken() {
        ApplicationClient client = new ApplicationClient();
        client.setClientId("test-client");
        client.setApplication(membershipApplication.getApplication());

        String token = jwtService.generateClientToken(client);

        assertNotNull(token);
        assertTrue(jwtService.isClientTokenValid(token));

        assertEquals("test-client", jwtService.extractClientId(token));
        assertEquals("test-app", jwtService.extractClientAppKey(token));
    }

    @Test
    void shouldRejectUserTokenAsClientToken() {
        String token = jwtService.generateToken(membershipApplication, sessionId);

        assertFalse(jwtService.isClientTokenValid(token));
    }

    @Test
    void shouldRejectClientTokenAsUserToken() {
        ApplicationClient client = new ApplicationClient();
        client.setClientId("test-client");
        client.setApplication(membershipApplication.getApplication());

        String token = jwtService.generateClientToken(client);

        assertFalse(jwtService.isTokenValid(token));
    }

    @Test
    void shouldRejectExpiredClientToken() {
        String token = createClientToken(
                CLIENT_SECRET,
                "test-client",
                "test-app",
                new Date(System.currentTimeMillis() - 10000));

        assertFalse(jwtService.isClientTokenValid(token));
    }

    @Test
    void shouldRejectClientTokenWithInvalidSignature() {
        String token = createClientToken(
                USER_SECRET,
                "test-client",
                "test-app",
                new Date(System.currentTimeMillis() + 60000));

        assertFalse(jwtService.isClientTokenValid(token));
    }

    @Test
    void shouldRejectClientTokenWithWrongTokenType() {
        String token = Jwts.builder()
                .setSubject("test-client")
                .setIssuer("authservice")
                .setAudience("authservice")
                .claim("token_type", "user")
                .claim("appKey", "test-app")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(
                        Keys.hmacShaKeyFor(Base64.getDecoder().decode(CLIENT_SECRET)),
                        SignatureAlgorithm.HS512)
                .compact();

        assertFalse(jwtService.isClientTokenValid(token));
    }

    private String createClientToken(
            String secret,
            String clientId,
            String appKey,
            Date expiration) {

        return Jwts.builder()
                .setSubject(clientId)
                .setIssuer("authservice")
                .setAudience("authservice")
                .claim("token_type", "client")
                .claim("appKey", appKey)
                .setIssuedAt(new Date())
                .setExpiration(expiration)
                .signWith(
                        Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret)),
                        SignatureAlgorithm.HS512)
                .compact();
    }

    @Test
    void shouldGenerateDifferentTokensForDifferentSessions() {
        UUID firstSession = UUID.randomUUID();
        UUID secondSession = UUID.randomUUID();

        String firstToken = jwtService.generateToken(membershipApplication, firstSession);

        String secondToken = jwtService.generateToken(membershipApplication, secondSession);

        assertNotEquals(
                jwtService.extractSessionId(firstToken),
                jwtService.extractSessionId(secondToken));
    }

}
