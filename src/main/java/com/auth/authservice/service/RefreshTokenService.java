package com.auth.authservice.service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.auth.authservice.entity.RefreshToken;
import com.auth.authservice.entity.User;
import com.auth.authservice.repository.RefreshTokenRepository;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository repository;

    public RefreshTokenService(RefreshTokenRepository repository) {
        this.repository = repository;
    }

    public RefreshToken createRefreshToken(User user) {

        RefreshToken token = new RefreshToken();

        token.setUser(user);
        token.setToken(UUID.randomUUID().toString());
        token.setExpiryDate(
                Instant.now().plus(7, ChronoUnit.DAYS));
        token.setRevoked(false);
        token.setUsed(false);
        token.setTenantId(user.getTenantId());

        return repository.save(token);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {

        if (token.getExpiryDate().isBefore(Instant.now())) {

            repository.delete(token);

            throw new RuntimeException("Refresh token expired");
        }

        return token;
    }

    public RefreshToken validateAndRotate(String refreshToken) {

        RefreshToken token = repository
                .findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (token.isUsed() || token.isRevoked()) {

            revokeAllUserTokens(token.getUser());

            throw new RuntimeException("Refresh token reuse detected");
        }

        verifyExpiration(token);

        token.setUsed(true);
        token.setRevoked(true);
        repository.save(token);

        return token;

    }

    public RefreshToken rotateToken(RefreshToken oldToken) {
        return createRefreshToken(oldToken.getUser());
    }

    public void revokeAllUserTokens(User user) {

        var tokens = repository.findAllByUserAndRevokedFalse(user);

        tokens.forEach(t -> {
            t.setUsed(true);
            t.setRevoked(true);
        });

        repository.saveAll(tokens);
    }

}
