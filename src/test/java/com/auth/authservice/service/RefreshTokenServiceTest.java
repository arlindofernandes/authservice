package com.auth.authservice.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.auth.authservice.entity.RefreshToken;
import com.auth.authservice.entity.User;
import com.auth.authservice.repository.RefreshTokenRepository;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class RefreshTokenServiceTest {

    @Test
    void rotatesATokenWithoutPersistingItsRawValue() {
        List<RefreshToken> savedTokens = new ArrayList<>();
        RefreshTokenRepository repository = repository(savedTokens);
        AuthMetrics authMetrics = new AuthMetrics(new SimpleMeterRegistry(), membershipRequestRepository());
        RefreshTokenService service = new RefreshTokenService(repository, authMetrics);
        User user = user();

        String originalRawToken = service.createRefreshToken(user);
        RefreshToken originalToken = savedTokens.getFirst();

        RefreshTokenService.RotatedRefreshToken rotated = service.rotate(originalRawToken);

        assertThat(originalRawToken).isNotEqualTo(originalToken.getTokenHash());
        assertThat(originalToken.getTokenHash()).hasSize(64);
        assertThat(originalToken.isUsed()).isTrue();
        assertThat(originalToken.isRevoked()).isTrue();
        assertThat(rotated.token()).isNotEqualTo(originalRawToken);
        assertThat(savedTokens).hasSize(2);
        assertThat(rotated.token()).isNotEqualTo(savedTokens.get(1).getTokenHash());
    }

    private com.auth.authservice.repository.MembershipRequestRepository membershipRequestRepository() {
        return (com.auth.authservice.repository.MembershipRequestRepository) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] { com.auth.authservice.repository.MembershipRequestRepository.class },
                (proxy, method, args) -> {
                    if (method.getName().equals("count")) {
                        return 0L;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private RefreshTokenRepository repository(List<RefreshToken> savedTokens) {
        return (RefreshTokenRepository) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] { RefreshTokenRepository.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "save" -> {
                        RefreshToken token = (RefreshToken) args[0];
                        if (!savedTokens.contains(token)) {
                            savedTokens.add(token);
                        }
                        yield token;
                    }
                    case "findByTokenHashForUpdate" -> savedTokens.stream()
                            .filter(token -> token.getTokenHash().equals(args[0]))
                            .findFirst();
                    case "findAllByUserAndRevokedFalse" -> List.of();
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private User user() {
        User user = new User();
        user.setTenantId(UUID.randomUUID());
        return user;
    }
}
