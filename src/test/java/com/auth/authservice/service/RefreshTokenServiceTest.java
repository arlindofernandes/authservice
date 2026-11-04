
package com.auth.authservice.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.auth.authservice.entity.MembershipApplication;
import com.auth.authservice.entity.RefreshToken;
import com.auth.authservice.repository.RefreshTokenRepository;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository repository;

    private RefreshTokenService refreshTokenService;

    private MembershipApplication membershipApplication;

    @BeforeEach
    void setUp() {
        refreshTokenService = new RefreshTokenService(repository);
        membershipApplication = new MembershipApplication();
    }

    @Test
    void shouldCreateRefreshTokenSuccessfully() {
        when(repository.save(any(RefreshToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        Instant beforeCreation = Instant.now();
        UUID sessionId = UUID.randomUUID();
        RefreshToken result = refreshTokenService.createRefreshToken(membershipApplication, sessionId);

        Instant afterCreation = Instant.now();
        assertEquals(sessionId, result.getSessionId());
        assertNotNull(result.getToken());
        assertDoesNotThrow(() -> java.util.UUID.fromString(result.getToken()));

        assertEquals(membershipApplication, result.getMembershipApplication());

        assertFalse(result.isRevoked());
        assertFalse(result.isUsed());

        assertFalse(result.getExpiryDate().isBefore(
                beforeCreation.plus(7, java.time.temporal.ChronoUnit.DAYS)));

        assertFalse(result.getExpiryDate().isAfter(
                afterCreation.plus(7, java.time.temporal.ChronoUnit.DAYS)));

        verify(repository).save(any(RefreshToken.class));
    }

    @Test
    void shouldValidateAndRotateRefreshToken() {
        RefreshToken token = createValidToken();

        when(repository.findByTokenForUpdate(token.getToken()))
                .thenReturn(Optional.of(token));

        when(repository.save(token)).thenReturn(token);

        RefreshToken result = refreshTokenService.validateAndRotate(token.getToken());

        assertEquals(token, result);
        assertTrue(result.isUsed());
        assertTrue(result.isRevoked());

        verify(repository).save(token);
    }

    @Test
    void shouldRejectUnknownRefreshToken() {
        when(repository.findByTokenForUpdate("unknown-token"))
                .thenReturn(Optional.empty());

        assertThrows(
                InvalidRefreshTokenException.class,
                () -> refreshTokenService.validateAndRotate("unknown-token"));
    }

    @Test
    void shouldRejectExpiredRefreshToken() {
        RefreshToken token = createValidToken();
        token.setExpiryDate(Instant.now().minusSeconds(60));

        when(repository.findByTokenForUpdate(token.getToken()))
                .thenReturn(Optional.of(token));

        assertThrows(
                InvalidRefreshTokenException.class,
                () -> refreshTokenService.validateAndRotate(token.getToken()));

        verify(repository).delete(token);
    }

    @Test
    void shouldDetectReuseAndRevokeActiveTokens() {
        RefreshToken reusedToken = createValidToken();
        reusedToken.setUsed(true);
        reusedToken.setRevoked(true);

        RefreshToken anotherActiveToken = createValidToken();

        when(repository.findByTokenForUpdate(reusedToken.getToken()))
                .thenReturn(Optional.of(reusedToken));

        when(repository.findAllByMembershipApplicationAndRevokedFalse(
                membershipApplication))
                .thenReturn(List.of(anotherActiveToken));

        assertThrows(
                RefreshTokenReuseException.class,
                () -> refreshTokenService.validateAndRotate(
                        reusedToken.getToken()));

        assertTrue(anotherActiveToken.isUsed());
        assertTrue(anotherActiveToken.isRevoked());

        verify(repository).saveAll(List.of(anotherActiveToken));
    }

    @Test
    void shouldRejectRevokedRefreshToken() {
        RefreshToken token = createValidToken();
        token.setRevoked(true);

        when(repository.findByTokenForUpdate(token.getToken()))
                .thenReturn(Optional.of(token));

        when(repository.findAllByMembershipApplicationAndRevokedFalse(
                membershipApplication))
                .thenReturn(List.of());

        assertThrows(
                RefreshTokenReuseException.class,
                () -> refreshTokenService.validateAndRotate(token.getToken()));
    }

    @Test
    void shouldRevokeAllActiveTokensOfMembershipApplication() {
        RefreshToken token1 = createValidToken();
        RefreshToken token2 = createValidToken();

        when(repository.findAllByMembershipApplicationAndRevokedFalse(
                membershipApplication))
                .thenReturn(List.of(token1, token2));

        refreshTokenService.revokeAllMembershipApplicationTokens(
                membershipApplication);

        assertTrue(token1.isRevoked());
        assertTrue(token1.isUsed());
        assertTrue(token2.isRevoked());
        assertTrue(token2.isUsed());

        verify(repository).saveAll(List.of(token1, token2));
    }

    @Test
    void shouldNotDeleteValidRefreshTokenDuringExpirationCheck() {
        RefreshToken token = createValidToken();

        RefreshToken result = refreshTokenService.verifyExpiration(token);

        assertEquals(token, result);
        verify(repository, never()).delete(any(RefreshToken.class));
    }

    private RefreshToken createValidToken() {
        RefreshToken token = new RefreshToken();

        token.setToken(java.util.UUID.randomUUID().toString());
        token.setMembershipApplication(membershipApplication);
        token.setSessionId(UUID.randomUUID());
        token.setExpiryDate(Instant.now().plusSeconds(3600));
        token.setRevoked(false);
        token.setUsed(false);

        return token;
    }

    @Test
    void shouldRevokeOnlyTokensFromTargetSession() {

        UUID firstSessionId = UUID.randomUUID();
        UUID secondSessionId = UUID.randomUUID();

        RefreshToken firstToken = createValidToken();
        firstToken.setSessionId(firstSessionId);

        RefreshToken secondToken = createValidToken();
        secondToken.setSessionId(firstSessionId);

        RefreshToken otherSessionToken = createValidToken();
        otherSessionToken.setSessionId(secondSessionId);

        when(repository.findAllBySessionIdAndRevokedFalse(firstSessionId))
                .thenReturn(List.of(firstToken, secondToken));

        refreshTokenService.revokeSession(firstSessionId);

        assertTrue(firstToken.isRevoked());
        assertTrue(firstToken.isUsed());

        assertTrue(secondToken.isRevoked());
        assertTrue(secondToken.isUsed());

        assertFalse(otherSessionToken.isRevoked());
        assertFalse(otherSessionToken.isUsed());

        verify(repository).saveAll(List.of(firstToken, secondToken));
    }
}
