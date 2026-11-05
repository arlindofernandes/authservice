
package com.auth.authservice.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import com.auth.authservice.entity.MembershipApplication;
import com.auth.authservice.entity.RefreshToken;
import com.auth.authservice.repository.MembershipApplicationRepository;
import com.auth.authservice.repository.RefreshTokenRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
class RefreshTokenConcurrencyIntegrationTest {

        @Container
        static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:15-alpine");

        @Container
        static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
                        .withExposedPorts(6379);

        @DynamicPropertySource
        static void configureProperties(DynamicPropertyRegistry registry) {
                registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
                registry.add("spring.datasource.username", POSTGRES::getUsername);
                registry.add("spring.datasource.password", POSTGRES::getPassword);

                registry.add("spring.data.redis.host", REDIS::getHost);
                registry.add("spring.data.redis.port",
                                () -> REDIS.getMappedPort(6379));

                registry.add("spring.flyway.enabled", () -> true);
                registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        }

        @Autowired
        private PlatformTransactionManager transactionManager;
        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private JwtService jwtService;
        @Autowired
        private RefreshTokenService refreshTokenService;

        @Autowired
        private RefreshTokenRepository refreshTokenRepository;

        @Autowired
        private MembershipApplicationRepository membershipApplicationRepository;

        @Autowired
        private JdbcTemplate jdbcTemplate;

        @Autowired
        private PasswordEncoder passwordEncoder;

        @Autowired
        private ObjectMapper objectMapper;

        private String testTenantSlug;
        private String testEmail;

        private static final String TEST_PASSWORD = "Test@123456";
        private static final String TEST_APP_KEY = "tempora";

        private MembershipApplication membershipApplication;

        private record LogoutReuseFixture(
                        String accessTokenA,
                        RefreshToken refreshTokenA,
                        RefreshToken refreshTokenB) {
        }

        @BeforeEach
        void setUp() {
                createTestMembershipApplication();
        }

        private void createTestMembershipApplication() {
                UUID tenantId = UUID.randomUUID();
                UUID userId = UUID.randomUUID();
                UUID membershipId = UUID.randomUUID();
                UUID tenantApplicationId = UUID.randomUUID();
                UUID membershipApplicationId = UUID.randomUUID();

                UUID applicationId = jdbcTemplate.queryForObject(
                                "SELECT id FROM application WHERE app_key = ?",
                                UUID.class,
                                "tempora");

                String unique = UUID.randomUUID().toString().replace("-", "");

                testTenantSlug = "teste-" + unique;
                testEmail = "teste-" + unique + "@example.com";

                jdbcTemplate.update("""
                                INSERT INTO tenant (id, name, slug, active)
                                VALUES (?, ?, ?, TRUE)
                                """,
                                tenantId,
                                "Tenant de teste",
                                testTenantSlug);

                jdbcTemplate.update("""
                                INSERT INTO users (id, name, email, password, enabled)
                                VALUES (?, ?, ?, ?, TRUE)
                                """,
                                userId,
                                "Usuário de teste",
                                testEmail,
                                passwordEncoder.encode(TEST_PASSWORD));

                jdbcTemplate.update("""
                                INSERT INTO tenant_membership
                                    (id, user_id, tenant_id, status)
                                VALUES (?, ?, ?, 'ACTIVE')
                                """,
                                membershipId,
                                userId,
                                tenantId);

                jdbcTemplate.update("""
                                INSERT INTO tenant_application
                                    (id, tenant_id, application_id, status)
                                VALUES (?, ?, ?, 'ACTIVE')
                                """,
                                tenantApplicationId,
                                tenantId,
                                applicationId);

                jdbcTemplate.update("""
                                INSERT INTO membership_application
                                    (id, tenant_id, application_id, membership_id,
                                     tenant_application_id, status)
                                VALUES (?, ?, ?, ?, ?, 'ACTIVE')
                                """,
                                membershipApplicationId,
                                tenantId,
                                applicationId,
                                membershipId,
                                tenantApplicationId);

                int rolesInserted = jdbcTemplate.update("""
                                INSERT INTO membership_application_roles (
                                    membership_application_id,
                                    role_id,
                                    application_id
                                )
                                SELECT ?, r.id, r.application_id
                                FROM role r
                                WHERE r.application_id = ?
                                  AND r.name = ?
                                """,
                                membershipApplicationId,
                                applicationId,
                                "USER");

                assertEquals(1, rolesInserted,
                                "A role USER deveria existir para a aplicação B");

                membershipApplication = membershipApplicationRepository
                                .findById(membershipApplicationId)
                                .orElseThrow();
        }

        @Test
        void shouldConsumeAndRevokeValidRefreshToken() {
                UUID sessionId = UUID.randomUUID();
                RefreshToken token = refreshTokenService.createRefreshToken(membershipApplication, sessionId);

                RefreshToken consumed = refreshTokenService.validateAndRotate(token.getToken());

                assertTrue(consumed.isUsed());
                assertTrue(consumed.isRevoked());

                RefreshToken persisted = refreshTokenRepository
                                .findById(token.getId())
                                .orElseThrow();

                assertTrue(persisted.isUsed());
                assertTrue(persisted.isRevoked());
        }

        @Test
        void shouldDeleteExpiredRefreshToken() {
                UUID sessionId = UUID.randomUUID();
                RefreshToken token = refreshTokenService.createRefreshToken(membershipApplication, sessionId);

                token.setExpiryDate(Instant.now().minusSeconds(60));
                refreshTokenRepository.save(token);

                assertThrows(
                                InvalidRefreshTokenException.class,
                                () -> refreshTokenService.validateAndRotate(token.getToken()));

                assertFalse(refreshTokenRepository.existsById(token.getId()));
        }

        @Test
        void shouldRevokeAllActiveTokensWhenReuseIsDetected() {
                UUID sessionId = UUID.randomUUID();
                RefreshToken first = refreshTokenService.createRefreshToken(membershipApplication, sessionId);

                RefreshToken second = refreshTokenService.createRefreshToken(membershipApplication, sessionId);

                // Primeiro uso: válido.
                refreshTokenService.validateAndRotate(first.getToken());

                // Segundo uso do mesmo token: reutilização.
                assertThrows(
                                RefreshTokenReuseException.class,
                                () -> refreshTokenService.validateAndRotate(first.getToken()));

                RefreshToken persistedSecond = refreshTokenRepository
                                .findById(second.getId())
                                .orElseThrow();

                assertTrue(persistedSecond.isRevoked());
                assertTrue(persistedSecond.isUsed());
        }

        @Test
        void shouldAllowOnlyOneRequestToConsumeTokenConcurrently()
                        throws Exception {
                UUID sessionId = UUID.randomUUID();
                RefreshToken token = refreshTokenService.createRefreshToken(membershipApplication, sessionId);

                ExecutorService executor = Executors.newFixedThreadPool(2);

                CountDownLatch ready = new CountDownLatch(2);
                CountDownLatch start = new CountDownLatch(1);

                try {
                        var attempt = (java.util.concurrent.Callable<Boolean>) () -> {
                                ready.countDown();

                                if (!start.await(5, TimeUnit.SECONDS)) {
                                        throw new IllegalStateException(
                                                        "Timeout aguardando início dos testes concorrentes");
                                }

                                try {
                                        refreshTokenService.validateAndRotate(token.getToken());
                                        return true;
                                } catch (RefreshTokenReuseException exception) {
                                        return false;
                                }
                        };

                        Future<Boolean> first = executor.submit(attempt);
                        Future<Boolean> second = executor.submit(attempt);

                        assertTrue(ready.await(5, TimeUnit.SECONDS));

                        // Libera as duas requisições simultaneamente.
                        start.countDown();

                        boolean firstSucceeded = first.get(15, TimeUnit.SECONDS);
                        boolean secondSucceeded = second.get(15, TimeUnit.SECONDS);

                        // Exatamente uma requisição deve consumir o token.
                        assertNotEquals(firstSucceeded, secondSucceeded);

                        RefreshToken persisted = refreshTokenRepository
                                        .findById(token.getId())
                                        .orElseThrow();

                        assertTrue(persisted.isUsed());
                        assertTrue(persisted.isRevoked());

                } finally {
                        start.countDown();
                        executor.shutdownNow();
                }
        }

        @Test
        void shouldRevokeOnlyTokensFromTargetSession() {

                UUID firstSessionId = UUID.randomUUID();
                UUID secondSessionId = UUID.randomUUID();

                RefreshToken firstSessionToken1 = refreshTokenService.createRefreshToken(
                                membershipApplication,
                                firstSessionId);

                RefreshToken firstSessionToken2 = refreshTokenService.createRefreshToken(
                                membershipApplication,
                                firstSessionId);

                RefreshToken secondSessionToken = refreshTokenService.createRefreshToken(
                                membershipApplication,
                                secondSessionId);

                refreshTokenService.revokeSession(firstSessionId);

                RefreshToken persistedFirst1 = refreshTokenRepository
                                .findById(firstSessionToken1.getId())
                                .orElseThrow();

                RefreshToken persistedFirst2 = refreshTokenRepository
                                .findById(firstSessionToken2.getId())
                                .orElseThrow();

                RefreshToken persistedSecond = refreshTokenRepository
                                .findById(secondSessionToken.getId())
                                .orElseThrow();

                assertTrue(persistedFirst1.isRevoked());
                assertTrue(persistedFirst1.isUsed());

                assertTrue(persistedFirst2.isRevoked());
                assertTrue(persistedFirst2.isUsed());

                assertFalse(persistedSecond.isRevoked());
                assertFalse(persistedSecond.isUsed());
        }

        @Test
        @Transactional
        void shouldLogoutOnlyCurrentSession() throws Exception {

                // Duas sessões do mesmo usuário.
                UUID sessionA = UUID.randomUUID();
                UUID sessionB = UUID.randomUUID();

                // Access tokens independentes.
                String accessTokenA = jwtService.generateToken(
                                membershipApplication,
                                sessionA);

                String accessTokenB = jwtService.generateToken(
                                membershipApplication,
                                sessionB);

                // Refresh tokens vinculados às respectivas sessões.
                RefreshToken refreshTokenA = refreshTokenService.createRefreshToken(
                                membershipApplication,
                                sessionA);

                RefreshToken refreshTokenB = refreshTokenService.createRefreshToken(
                                membershipApplication,
                                sessionB);

                // Logout somente da sessão A.
                mockMvc.perform(post("/auth/logout")
                                .header("Authorization", "Bearer " + accessTokenA))
                                .andExpect(status().isNoContent());

                // O access token A deve estar invalidado.
                mockMvc.perform(get("/api/user")
                                .header("Authorization", "Bearer " + accessTokenA))
                                .andExpect(status().isUnauthorized());

                // O access token B deve continuar funcionando.
                mockMvc.perform(get("/api/user")
                                .header("Authorization", "Bearer " + accessTokenB))
                                .andExpect(status().isOk())
                                .andExpect(content().string("Acesso user"));

                // Confere a situação dos refresh tokens no banco.
                RefreshToken persistedA = refreshTokenRepository
                                .findById(refreshTokenA.getId())
                                .orElseThrow();

                RefreshToken persistedB = refreshTokenRepository
                                .findById(refreshTokenB.getId())
                                .orElseThrow();

                assertTrue(persistedA.isRevoked());
                assertTrue(persistedA.isUsed());

                assertFalse(persistedB.isRevoked());
                assertFalse(persistedB.isUsed());
        }

        @Test
        void shouldRevokeAllSessionsWhenLoggedOutRefreshTokenIsReused()
                        throws Exception {

                TransactionTemplate transactionTemplate = new TransactionTemplate(transactionManager);

                // Cria e persiste os tokens em uma transação independente.
                LogoutReuseFixture fixture = Objects.requireNonNull(
                                transactionTemplate.execute(status -> {

                                        MembershipApplication membership = membershipApplicationRepository
                                                        .findById(membershipApplication.getId())
                                                        .orElseThrow();

                                        UUID sessionA = UUID.randomUUID();
                                        UUID sessionB = UUID.randomUUID();

                                        String accessTokenA = jwtService.generateToken(
                                                        membership,
                                                        sessionA);

                                        RefreshToken refreshTokenA = refreshTokenService.createRefreshToken(
                                                        membership,
                                                        sessionA);

                                        RefreshToken refreshTokenB = refreshTokenService.createRefreshToken(
                                                        membership,
                                                        sessionB);

                                        return new LogoutReuseFixture(
                                                        accessTokenA,
                                                        refreshTokenA,
                                                        refreshTokenB);
                                }),
                                "A transação não retornou a fixture");

                // O logout revoga a sessão A.
                mockMvc.perform(post("/auth/logout")
                                .header("Authorization", "Bearer " + fixture.accessTokenA()))
                                .andExpect(status().isNoContent());

                // Tenta reutilizar o refresh token revogado.
                assertThrows(
                                RefreshTokenReuseException.class,
                                () -> refreshTokenService.validateAndRotate(
                                                fixture.refreshTokenA().getToken()));

                // Verifica o estado persistido dos dois tokens.
                RefreshToken persistedA = refreshTokenRepository
                                .findById(fixture.refreshTokenA().getId())
                                .orElseThrow();

                RefreshToken persistedB = refreshTokenRepository
                                .findById(fixture.refreshTokenB().getId())
                                .orElseThrow();

                assertTrue(persistedA.isRevoked());
                assertTrue(persistedA.isUsed());

                assertTrue(persistedB.isRevoked());
                assertTrue(persistedB.isUsed());
        }

        @Test
        void shouldRefreshTokensThroughHttpEndpoint() throws Exception {

                String loginRequest = """
                                {
                                    "tenantSlug": "%s",
                                    "appKey": "%s",
                                    "email": "%s",
                                    "password": "%s"
                                }
                                """.formatted(
                                testTenantSlug,
                                TEST_APP_KEY,
                                testEmail,
                                TEST_PASSWORD);

                String loginResponse = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(loginRequest))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                                .andReturn()
                                .getResponse()
                                .getContentAsString();

                var loginJson = objectMapper.readTree(loginResponse);

                String oldRefreshToken = loginJson.get("refreshToken").asText();

                String refreshRequest = """
                                {
                                    "refreshToken": "%s"
                                }
                                """.formatted(oldRefreshToken);

                String refreshResponse = mockMvc.perform(post("/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshRequest))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                                .andReturn()
                                .getResponse()
                                .getContentAsString();

                String refreshJson = objectMapper.readTree(refreshResponse)
                                .get("refreshToken")
                                .asText();

                String newRefreshToken = refreshJson;

                assertNotEquals(oldRefreshToken, newRefreshToken);
        }

        @Test
        void shouldRevokeAllTokensWhenRefreshTokenIsReusedThroughHttpEndpoint()
                        throws Exception {

                // 1. Realiza login e obtém o primeiro refresh token.
                String loginRequest = """
                                {
                                    "tenantSlug": "%s",
                                    "appKey": "%s",
                                    "email": "%s",
                                    "password": "%s"
                                }
                                """.formatted(
                                testTenantSlug,
                                TEST_APP_KEY,
                                testEmail,
                                TEST_PASSWORD);

                String loginResponse = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(loginRequest))
                                .andExpect(status().isOk())
                                .andReturn()
                                .getResponse()
                                .getContentAsString();

                String firstRefreshToken = objectMapper.readTree(loginResponse)
                                .get("refreshToken")
                                .asText();

                // 2. Renova o token pela primeira vez.
                String firstRefreshRequest = """
                                {
                                    "refreshToken": "%s"
                                }
                                """.formatted(firstRefreshToken);

                String refreshResponse = mockMvc.perform(post("/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(firstRefreshRequest))
                                .andExpect(status().isOk())
                                .andReturn()
                                .getResponse()
                                .getContentAsString();

                String secondRefreshToken = objectMapper.readTree(refreshResponse)
                                .get("refreshToken")
                                .asText();

                assertNotEquals(firstRefreshToken, secondRefreshToken);

                // 3. Reutiliza o primeiro token, que já foi consumido.
                mockMvc.perform(post("/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(firstRefreshRequest))
                                .andExpect(status().isUnauthorized());

                // 4. Consulta os tokens persistidos.
                var persistedTokens = refreshTokenRepository.findAll()
                                .stream()
                                .filter(token -> token.getMembershipApplication().getId()
                                                .equals(membershipApplication.getId()))
                                .toList();

                // 5. Todos os tokens devem estar usados e revogados.
                assertFalse(persistedTokens.isEmpty());

                for (RefreshToken token : persistedTokens) {
                        assertTrue(token.isUsed(),
                                        "Todos os refresh tokens devem estar marcados como usados");

                        assertTrue(token.isRevoked(),
                                        "Todos os refresh tokens devem estar revogados");
                }
        }

        @Test
        void shouldPreserveRefreshTokenWhenMembershipApplicationIsSuspended() throws Exception {

                // Realiza login e obtém um refresh token válido.
                String loginRequest = """
                                {
                                    "tenantSlug": "%s",
                                    "appKey": "%s",
                                    "email": "%s",
                                    "password": "%s"
                                }
                                """.formatted(
                                testTenantSlug,
                                TEST_APP_KEY,
                                testEmail,
                                TEST_PASSWORD);

                String loginResponse = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(loginRequest))
                                .andExpect(status().isOk())
                                .andReturn()
                                .getResponse()
                                .getContentAsString();

                String refreshToken = objectMapper.readTree(loginResponse)
                                .get("refreshToken")
                                .asText();
                // Suspende a associação à aplicação.
                membershipApplication.setStatus(MembershipApplication.Status.SUSPENDED);
                membershipApplicationRepository.saveAndFlush(membershipApplication);

                String refreshRequest = """
                                {
                                    "refreshToken": "%s"
                                }
                                """.formatted(refreshToken);

                // A renovação deve ser recusada.
                mockMvc.perform(post("/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshRequest))
                                .andExpect(status().isUnauthorized());

                // O token original deve continuar válido no banco.
                RefreshToken persistedToken = refreshTokenRepository
                                .findAll()
                                .stream()
                                .filter(token -> token.getToken().equals(refreshToken))
                                .findFirst()
                                .orElseThrow();

                assertFalse(persistedToken.isUsed());
                assertFalse(persistedToken.isRevoked());
        }
}
