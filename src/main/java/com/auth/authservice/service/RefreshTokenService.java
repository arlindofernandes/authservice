package com.auth.authservice.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auth.authservice.entity.RefreshToken;
import com.auth.authservice.entity.User;
import com.auth.authservice.repository.RefreshTokenRepository;

@Service
public class RefreshTokenService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final RefreshTokenRepository repository;

    public RefreshTokenService(RefreshTokenRepository repository) {
        this.repository = repository;
    }

    public String createRefreshToken(User user) {
        return issueRefreshToken(user).token();
    }

    @Transactional(noRollbackFor = RefreshTokenValidationException.class)
    public RotatedRefreshToken rotate(String rawToken) {
        RefreshToken token = repository
                .findByTokenHashForUpdate(hash(rawToken))
                .orElseThrow(() -> new RefreshTokenValidationException("Invalid refresh token"));

        if (!token.getTenantId().equals(token.getUser().getTenantId())) {
            token.setUsed(true);
            token.setRevoked(true);
            repository.save(token);
            throw new RefreshTokenValidationException("Refresh token tenant mismatch");
        }

        if (token.isUsed() || token.isRevoked()) {
            revokeAllUserTokens(token.getUser());
            throw new RefreshTokenValidationException("Refresh token reuse detected");
        }

        if (token.getExpiryDate().isBefore(Instant.now())) {
            token.setUsed(true);
            token.setRevoked(true);
            repository.save(token);
            throw new RefreshTokenValidationException("Refresh token expired");
        }

        token.setUsed(true);
        token.setRevoked(true);
        repository.save(token);

        IssuedRefreshToken newToken = issueRefreshToken(token.getUser());
        return new RotatedRefreshToken(token.getUser(), newToken.token());
    }

    public void revokeAllUserTokens(User user) {
        var tokens = repository.findAllByUserAndRevokedFalse(user);
        tokens.forEach(token -> {
            token.setUsed(true);
            token.setRevoked(true);
        });
        repository.saveAll(tokens);
    }

    private IssuedRefreshToken issueRefreshToken(User user) {
        RefreshToken token = new RefreshToken();
        String rawToken = generateRawToken();

        token.setUser(user);
        token.setTokenHash(hash(rawToken));
        token.setExpiryDate(Instant.now().plus(7, ChronoUnit.DAYS));
        token.setRevoked(false);
        token.setUsed(false);
        token.setTenantId(user.getTenantId());

        return new IssuedRefreshToken(repository.save(token), rawToken);
    }

    private String generateRawToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }

    private record IssuedRefreshToken(RefreshToken entity, String token) {
    }

    public record RotatedRefreshToken(User user, String token) {
    }
}
