package com.auth.authservice;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.lang.NonNull;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest(properties = "management.defaults.metrics.export.enabled=true")
@AutoConfigureMockMvc
class AuthenticationIntegrationTest {

        @SuppressWarnings("resource")
        @Container
        static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:15-alpine")
                        .withDatabaseName("authservice")
                        .withUsername("auth")
                        .withPassword("auth");

        @SuppressWarnings("resource")
        @Container
        static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
                        .withExposedPorts(6379);

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private ObjectMapper objectMapper;

        @Autowired
        private JdbcTemplate jdbcTemplate;

        @Autowired
        private StringRedisTemplate redisTemplate;

        @DynamicPropertySource
        static void configureProperties(DynamicPropertyRegistry registry) {
                registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
                registry.add("spring.datasource.username", POSTGRES::getUsername);
                registry.add("spring.datasource.password", POSTGRES::getPassword);
                registry.add("spring.data.redis.host", REDIS::getHost);
                registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
                registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
                registry.add("spring.jpa.show-sql", () -> false);
        }

        @BeforeEach
        void cleanDatabase() {
                jdbcTemplate.execute(
                                "TRUNCATE TABLE refresh_token, user_roles, users, tenant CASCADE");

                var connectionFactory = requireNonNull(
                                redisTemplate.getConnectionFactory(),
                                "RedisConnectionFactory não está configurada");

                try (var connection = connectionFactory.getConnection()) {
                        connection.serverCommands().flushDb();
                }
        }

        @Test
        void authenticatesRolesRotatesRefreshTokensAndInvalidatesLoggedOutTokens() throws Exception {
                JsonNode admin = register("admin@acme.test", "AdminSecret123", "Acme");

                String adminAccessToken = requireNonNull(admin.required("accessToken").asText());
                String adminRefreshToken = requireNonNull(admin.required("refreshToken").asText());

                mockMvc.perform(get("/api/admin").header("Authorization", "Bearer " + adminAccessToken))
                                .andExpect(status().isOk());
                mockMvc.perform(get("/api/user").header("Authorization", "Bearer " + adminAccessToken))
                                .andExpect(status().isForbidden());

                JsonNode rotated = refresh(adminRefreshToken, status().isOk());
                assertThat(rotated.required("refreshToken").asText()).isNotEqualTo(adminRefreshToken);

                Integer rawTokenRows = jdbcTemplate.queryForObject(
                                "select count(*) from refresh_token where token_hash = ?", Integer.class,
                                adminRefreshToken);
                Integer hashedTokenRows = jdbcTemplate.queryForObject(
                                "select count(*) from refresh_token where length(token_hash) = 64", Integer.class);
                assertThat(rawTokenRows).isZero();
                assertThat(hashedTokenRows).isGreaterThanOrEqualTo(2);

                String rotatedRefreshToken = rotated.required("refreshToken").asText();
                String rotatedAccessToken = rotated.required("accessToken").asText();

                mockMvc.perform(post("/auth/logout")
                                .header("Authorization", "Bearer " + rotatedAccessToken)
                                .contentType("application/json")
                                .content(requireNonNull(objectMapper.writeValueAsString(
                                                Map.of("refreshToken", rotatedRefreshToken)))))
                                .andExpect(status().isNoContent());

                // Um token já rotacionado não pode ser reutilizado.
                refresh(adminRefreshToken, status().isUnauthorized());

                // O refresh token revogado não pode ser reutilizado.
                refresh(requireNonNull(rotatedRefreshToken), status().isUnauthorized());

                // O access token também não pode mais ser utilizado.
                mockMvc.perform(get("/api/admin").header("Authorization", "Bearer " + rotatedAccessToken))
                                .andExpect(status().isUnauthorized());
        }

        private JsonNode register(@NonNull String email, @NonNull String password, @NonNull String tenantName)
                        throws Exception {
                MvcResult result = mockMvc.perform(post("/admin/tenants")
                                .header("X-Admin-Token", "local-development-admin-token")
                                .contentType("application/json")
                                .content(requireNonNull(objectMapper.writeValueAsString(Map.of(
                                                "email", email,
                                                "password", password,
                                                "tenantName", tenantName)))))
                                .andExpect(status().isCreated())
                                .andReturn();
                return objectMapper.readTree(result.getResponse().getContentAsString());
        }

        private JsonNode refresh(@NonNull String token, @NonNull ResultMatcher expectedStatus)
                        throws Exception {
                MvcResult result = mockMvc.perform(post("/auth/refresh")
                                .contentType("application/json")
                                .content(requireNonNull(
                                                objectMapper.writeValueAsString(Map.of("refreshToken", token)))))
                                .andExpect(expectedStatus)
                                .andReturn();
                return objectMapper.readTree(result.getResponse().getContentAsString());
        }

        @Test
        void isolatesAuthenticationBetweenTenants() throws Exception {
                JsonNode acmeAdmin = register(
                                "admin@acme.test",
                                "AdminSecret123",
                                "Acme");

                JsonNode betaAdmin = register(
                                "admin@beta.test",
                                "BetaSecret123",
                                "Beta");

                String acmeAccessToken = acmeAdmin.required("accessToken").asText();
                String betaAccessToken = betaAdmin.required("accessToken").asText();

                // O administrador do tenant Acme acessa sua própria área.
                mockMvc.perform(get("/api/admin")
                                .header("Authorization", "Bearer " + acmeAccessToken))
                                .andExpect(status().isOk());

                // O administrador do tenant Beta acessa sua própria área.
                mockMvc.perform(get("/api/admin")
                                .header("Authorization", "Bearer " + betaAccessToken))
                                .andExpect(status().isOk());
        }

        @Test
        void allowsSameEmailInDifferentTenants() throws Exception {
                JsonNode acmeUser = register(
                                "admin@company.test",
                                "Password123",
                                "Acme");

                JsonNode betaUser = register(
                                "admin@company.test",
                                "Password123",
                                "Beta");

                assertThat(acmeUser.hasNonNull("accessToken")).isTrue();
                assertThat(betaUser.hasNonNull("accessToken")).isTrue();

                Integer tenantCount = jdbcTemplate.queryForObject(
                                "SELECT COUNT(DISTINCT tenant_id) FROM users WHERE email = ?",
                                Integer.class,
                                "admin@company.test");

                assertThat(tenantCount).isEqualTo(2);
        }

        @Test
        void preventsRegistrationInAnExistingTenant() throws Exception {
                register(
                                "admin@company.test",
                                "Password123",
                                "Acme");

                mockMvc.perform(post("/admin/tenants")
                                .header("X-Admin-Token", "local-development-admin-token")
                                .contentType(requireNonNull(MediaType.APPLICATION_JSON))
                                .content(requireNonNull(objectMapper.writeValueAsString(Map.of(
                                                "email", "admin@company.test",
                                                "password", "Password123",
                                                "tenantName", "Acme")))))
                                .andExpect(status().isConflict());
        }

        @Test
        void rejectsPublicOrUnauthenticatedTenantRegistration() throws Exception {
                mockMvc.perform(post("/auth/register")
                                .contentType(requireNonNull(MediaType.APPLICATION_JSON))
                                .content("{}"))
                                .andExpect(status().isUnauthorized());

                mockMvc.perform(post("/admin/tenants")
                                .contentType(requireNonNull(MediaType.APPLICATION_JSON))
                                .content("{}"))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        void doesNotCreateHttpSession() throws Exception {
                MvcResult result = mockMvc.perform(get("/api/admin"))
                                .andExpect(status().isUnauthorized())
                                .andReturn();

                assertThat(result.getRequest().getSession(false)).isNull();
        }

        @Test
        void exposesOpenApiDocumentationWithoutAuthentication() throws Exception {
                mockMvc.perform(get("/v3/api-docs"))
                                .andExpect(status().isOk());
        }

        @Test
        void returnsTheSuppliedRequestIdForRequestCorrelation() throws Exception {
                mockMvc.perform(get("/v3/api-docs").header("X-Request-Id", "gateway-request-123"))
                                .andExpect(status().isOk())
                                .andExpect(result -> assertThat(result.getResponse().getHeader("X-Request-Id"))
                                                .isEqualTo("gateway-request-123"));
        }

        @Test
        void exposesPublicJwksForOtherMicroservicesToVerifyTokens() throws Exception {
                mockMvc.perform(get("/.well-known/jwks.json"))
                                .andExpect(status().isOk())
                                .andExpect(result -> assertThat(objectMapper.readTree(
                                                result.getResponse().getContentAsString()).at("/keys/0/kty").asText())
                                                .isEqualTo("RSA"));
        }

        @Test
        void exposesPrometheusMetricsOnlyWithPlatformAdminToken() throws Exception {
                mockMvc.perform(get("/actuator/prometheus"))
                                .andExpect(status().isUnauthorized());
                mockMvc.perform(get("/actuator/prometheus")
                                .header("X-Admin-Token", "local-development-admin-token"))
                                .andExpect(status().isOk());
        }

        @Test
        void exposesAuthenticationSecurityMetrics() throws Exception {
                register("admin@acme.test", "AdminSecret123", "Acme");
                login("acme", "admin@acme.test", "AdminSecret123", status().isOk());
                login("acme", "admin@acme.test", "wrong-password", status().isUnauthorized());

                mockMvc.perform(get("/actuator/prometheus")
                                .header("X-Admin-Token", "local-development-admin-token"))
                                .andExpect(status().isOk())
                                .andExpect(result -> assertThat(result.getResponse().getContentAsString())
                                                .contains("auth_logins_success_total", "auth_logins_failed_total",
                                                                "auth_membership_pending"));
        }

        @Test
        void exposesUnauthenticatedLivenessAndReadinessProbes() throws Exception {
                mockMvc.perform(get("/actuator/health/liveness"))
                                .andExpect(status().isOk());
                mockMvc.perform(get("/actuator/health/readiness"))
                                .andExpect(status().isOk());
        }

        @Test
        void preventsRegistrationInAnExistingTenantWithAnotherEmailDomain() throws Exception {
                register("admin@acme.test", "AdminSecret123", "Acme");

                mockMvc.perform(post("/admin/tenants")
                                .header("X-Admin-Token", "local-development-admin-token")
                                .contentType(requireNonNull(MediaType.APPLICATION_JSON))
                                .content(requireNonNull(objectMapper.writeValueAsString(Map.of(
                                                "email", "user@gmail.com",
                                                "password", "UserSecret123",
                                                "tenantName", "Acme")))))
                                .andExpect(status().isConflict());
        }

        @Test
        void createsUsersOnlyAfterTheirMembershipRequestIsApprovedByATenantAdmin() throws Exception {
                JsonNode admin = register("admin@acme.test", "AdminSecret123", "Acme");
                String adminAccessToken = admin.required("accessToken").asText();

                MvcResult requestResult = mockMvc.perform(post("/auth/membership-requests")
                                .contentType(requireNonNull(MediaType.APPLICATION_JSON))
                                .content(requireNonNull(objectMapper.writeValueAsString(Map.of(
                                                "tenantSlug", "acme",
                                                "email", "member@example.test",
                                                "password", "MemberSecret123")))))
                                .andExpect(status().isAccepted())
                                .andReturn();
                JsonNode membershipRequest = objectMapper.readTree(requestResult.getResponse().getContentAsString());
                String requestId = membershipRequest.required("id").asText();

                String storedPassword = jdbcTemplate.queryForObject(
                                "SELECT password FROM membership_request WHERE id = ?::uuid",
                                String.class,
                                requestId);
                assertThat(storedPassword).startsWith("$2").isNotEqualTo("MemberSecret123");

                login("acme", "member@example.test", "MemberSecret123", status().isUnauthorized());

                mockMvc.perform(get("/tenants/membership-requests")
                                .header("Authorization", "Bearer " + adminAccessToken))
                                .andExpect(status().isOk())
                                .andExpect(result -> assertThat(objectMapper.readTree(
                                                result.getResponse().getContentAsString()))
                                                .extracting(node -> node.required("id").asText())
                                                .containsExactly(requestId));

                mockMvc.perform(post("/tenants/membership-requests/{requestId}/approve", requestId)
                                .header("Authorization", "Bearer " + adminAccessToken))
                                .andExpect(status().isNoContent());

                JsonNode member = login("acme", "member@example.test", "MemberSecret123", status().isOk());
                String memberAccessToken = member.required("accessToken").asText();
                mockMvc.perform(get("/api/user").header("Authorization", "Bearer " + memberAccessToken))
                                .andExpect(status().isOk());
                mockMvc.perform(get("/api/admin").header("Authorization", "Bearer " + memberAccessToken))
                                .andExpect(status().isForbidden());
                mockMvc.perform(get("/tenants/membership-requests")
                                .header("Authorization", "Bearer " + memberAccessToken))
                                .andExpect(status().isForbidden());
        }

        @Test
        void rejectsDuplicateMembershipRequests() throws Exception {
                register("admin@acme.test", "AdminSecret123", "Acme");
                String body = requireNonNull(objectMapper.writeValueAsString(Map.of(
                                "tenantSlug", "acme",
                                "email", "member@example.test",
                                "password", "MemberSecret123")));

                mockMvc.perform(post("/auth/membership-requests")
                                .contentType(requireNonNull(MediaType.APPLICATION_JSON))
                                .content(body))
                                .andExpect(status().isAccepted());
                mockMvc.perform(post("/auth/membership-requests")
                                .contentType(requireNonNull(MediaType.APPLICATION_JSON))
                                .content(body))
                                .andExpect(status().isConflict());
        }

        @Test
        void preventsAnAdminFromApprovingAnotherTenantsMembershipRequest() throws Exception {
                JsonNode acmeAdmin = register("admin@acme.test", "AdminSecret123", "Acme");
                JsonNode betaAdmin = register("admin@beta.test", "BetaSecret123", "Beta");

                MvcResult requestResult = mockMvc.perform(post("/auth/membership-requests")
                                .contentType(requireNonNull(MediaType.APPLICATION_JSON))
                                .content(requireNonNull(objectMapper.writeValueAsString(Map.of(
                                                "tenantSlug", "acme",
                                                "email", "member@example.test",
                                                "password", "MemberSecret123")))))
                                .andExpect(status().isAccepted())
                                .andReturn();
                String requestId = objectMapper.readTree(requestResult.getResponse().getContentAsString())
                                .required("id").asText();

                mockMvc.perform(post("/tenants/membership-requests/{requestId}/approve", requestId)
                                .header("Authorization", "Bearer " + betaAdmin.required("accessToken").asText()))
                                .andExpect(status().isNotFound());

                mockMvc.perform(get("/tenants/membership-requests")
                                .header("Authorization", "Bearer " + acmeAdmin.required("accessToken").asText()))
                                .andExpect(status().isOk())
                                .andExpect(result -> assertThat(objectMapper.readTree(
                                                result.getResponse().getContentAsString()))
                                                .extracting(node -> node.required("id").asText())
                                                .containsExactly(requestId));
        }

        @Test
        void rejectsLoginAndExistingJwtAfterAUserIsDisabled() throws Exception {
                JsonNode admin = register("admin@acme.test", "AdminSecret123", "Acme");
                String accessToken = admin.required("accessToken").asText();

                jdbcTemplate.update("UPDATE users SET enabled = false WHERE email = ?", "admin@acme.test");

                login("acme", "admin@acme.test", "AdminSecret123", status().isUnauthorized());
                mockMvc.perform(get("/api/admin").header("Authorization", "Bearer " + accessToken))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        void limitsRepeatedFailedLoginAttempts() throws Exception {
                register("admin@acme.test", "AdminSecret123", "Acme");

                for (int attempt = 0; attempt < 5; attempt++) {
                        login("acme", "admin@acme.test", "wrong-password", status().isUnauthorized());
                }

                MvcResult result = mockMvc.perform(post("/auth/login")
                                .contentType(requireNonNull(MediaType.APPLICATION_JSON))
                                .content(requireNonNull(objectMapper.writeValueAsString(Map.of(
                                                "tenantSlug", "acme",
                                                "email", "admin@acme.test",
                                                "password", "wrong-password")))))
                                .andExpect(status().isTooManyRequests())
                                .andReturn();

                assertThat(result.getResponse().getHeader("Retry-After")).isEqualTo("60");
        }

        private JsonNode login(@NonNull String tenantSlug, @NonNull String email, @NonNull String password,
                        @NonNull ResultMatcher expectedStatus) throws Exception {
                MvcResult result = mockMvc.perform(post("/auth/login")
                                .contentType(requireNonNull(MediaType.APPLICATION_JSON))
                                .content(requireNonNull(objectMapper.writeValueAsString(Map.of(
                                                "tenantSlug", tenantSlug,
                                                "email", email,
                                                "password", password)))))
                                .andExpect(expectedStatus)
                                .andReturn();
                return objectMapper.readTree(result.getResponse().getContentAsString());
        }
}
