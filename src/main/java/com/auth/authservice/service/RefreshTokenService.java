package com.auth.authservice.service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.auth.authservice.entity.MembershipApplication;
import com.auth.authservice.entity.RefreshToken;
import com.auth.authservice.repository.RefreshTokenRepository;

import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository repository;

    public RefreshTokenService(RefreshTokenRepository repository) {
        this.repository = repository;
    }

    @Transactional
    public RefreshToken createRefreshToken(MembershipApplication membershipApplication) {

        RefreshToken token = new RefreshToken();

        token.setMembershipApplication(membershipApplication);
        token.setToken(UUID.randomUUID().toString());
        token.setExpiryDate(Instant.now().plus(7, ChronoUnit.DAYS));
        token.setRevoked(false);
        token.setUsed(false);

        return repository.save(token);
    }

    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public RefreshToken verifyExpiration(RefreshToken token) {

        if (token.getExpiryDate().isBefore(Instant.now())) {

            repository.delete(token);

            throw new InvalidRefreshTokenException();
        }

        return token;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW, noRollbackFor = {
            RefreshTokenReuseException.class,
            InvalidRefreshTokenException.class
    })
    public RefreshToken validateAndRotate(String refreshToken) {

        RefreshToken token = repository
                .findByToken(refreshToken)
                .orElseThrow(InvalidRefreshTokenException::new);

        MembershipApplication membershipApplication = token.getMembershipApplication();

        if (token.isUsed() || token.isRevoked()) {

            revokeAllMembershipApplicationTokens(membershipApplication);

            throw new RefreshTokenReuseException();
        }

        verifyExpiration(token);

        token.setUsed(true);
        token.setRevoked(true);

        return repository.save(token);
    }

    public RefreshToken rotateToken(RefreshToken oldToken) {
        return createRefreshToken(oldToken.getMembershipApplication());
    }

    @Transactional
    public void revokeAllMembershipApplicationTokens(
            MembershipApplication membershipApplication) {

        var tokens = repository
                .findAllByMembershipApplicationAndRevokedFalse(membershipApplication);

        tokens.forEach(token -> {
            token.setUsed(true);
            token.setRevoked(true);
        });

        repository.saveAll(tokens);
    }
}
