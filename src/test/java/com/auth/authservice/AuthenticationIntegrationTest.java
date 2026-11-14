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
import org.springframework.jdbc.core.JdbcTemplate;
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
@SpringBootTest
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
        }

        @Test
        void authenticatesRolesRotatesRefreshTokensAndInvalidatesLoggedOutTokens() throws Exception {
                JsonNode admin = register("admin@acme.test", "AdminSecret123", "Acme");
                JsonNode user = register("user@acme.test", "UserSecret123", "Acme");

                String adminAccessToken = requireNonNull(admin.required("accessToken").asText());
                String adminRefreshToken = requireNonNull(admin.required("refreshToken").asText());
                String userAccessToken = requireNonNull(user.required("accessToken").asText());
                String oldUserRefreshToken = requireNonNull(user.required("refreshToken").asText());

                mockMvc.perform(get("/api/admin").header("Authorization", "Bearer " + adminAccessToken))
                                .andExpect(status().isOk());
                mockMvc.perform(get("/api/user").header("Authorization", "Bearer " + userAccessToken))
                                .andExpect(status().isOk());
                mockMvc.perform(get("/api/admin").header("Authorization", "Bearer " + userAccessToken))
                                .andExpect(status().isForbidden());

                JsonNode rotated = refresh(oldUserRefreshToken, status().isOk());
                assertThat(rotated.required("refreshToken").asText()).isNotEqualTo(oldUserRefreshToken);

                refresh(oldUserRefreshToken, status().isUnauthorized());

                Integer rawTokenRows = jdbcTemplate.queryForObject(
                                "select count(*) from refresh_token where token_hash = ?", Integer.class,
                                oldUserRefreshToken);
                Integer hashedTokenRows = jdbcTemplate.queryForObject(
                                "select count(*) from refresh_token where length(token_hash) = 64", Integer.class);
                assertThat(rawTokenRows).isZero();
                assertThat(hashedTokenRows).isGreaterThanOrEqualTo(3);

                mockMvc.perform(post("/auth/logout")
                                .header("Authorization", "Bearer " + adminAccessToken)
                                .contentType("application/json")
                                .content(requireNonNull(objectMapper.writeValueAsString(
                                                Map.of("refreshToken", adminRefreshToken)))))
                                .andExpect(status().isNoContent());

                // O refresh token revogado não pode ser reutilizado.
                refresh(adminRefreshToken, status().isUnauthorized());

                // O access token também não pode mais ser utilizado.
                mockMvc.perform(get("/api/admin").header("Authorization", "Bearer " + adminAccessToken))
                                .andExpect(status().isUnauthorized());
        }

        private JsonNode register(@NonNull String email, @NonNull String password, @NonNull String tenantName)
                        throws Exception {
                MvcResult result = mockMvc.perform(post("/auth/register")
                                .contentType("application/json")
                                .content(requireNonNull(objectMapper.writeValueAsString(Map.of(
                                                "email", email,
                                                "password", password,
                                                "tenantName", tenantName)))))
                                .andExpect(status().isOk())
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
                                "admin@acme.test",
                                "Password123",
                                "Acme");

                JsonNode betaUser = register(
                                "admin@beta.test",
                                "Password123",
                                "Beta");

                assertThat(acmeUser.hasNonNull("accessToken")).isTrue();
                assertThat(betaUser.hasNonNull("accessToken")).isTrue();

                Integer tenantCount = jdbcTemplate.queryForObject(
                                "SELECT COUNT(DISTINCT tenant_id) FROM users WHERE email IN (?, ?)",
                                Integer.class,
                                "admin@acme.test",
                                "admin@beta.test");

                assertThat(tenantCount).isEqualTo(2);
        }

        @Test
        void doesNotCreateHttpSession() throws Exception {
                MvcResult result = mockMvc.perform(get("/api/admin"))
                                .andExpect(status().isUnauthorized())
                                .andReturn();

                assertThat(result.getRequest().getSession(false)).isNull();
        }
}
