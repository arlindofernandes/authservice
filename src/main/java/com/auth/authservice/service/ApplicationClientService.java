package com.auth.authservice.service;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auth.authservice.dto.ClientTokenResponse;
import com.auth.authservice.entity.ApplicationClient;
import com.auth.authservice.repository.ApplicationClientRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ApplicationClientService {

    private final ApplicationClientRepository applicationClientRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public ApplicationClient authenticate(String clientId, String clientSecret) {

        if (clientId == null || clientId.isBlank()
                || clientSecret == null || clientSecret.isBlank()) {
            throw new BadCredentialsException("Invalid client credentials");
        }

        ApplicationClient client = applicationClientRepository
                .findByClientIdAndActiveTrue(clientId)
                .orElseThrow(() -> new BadCredentialsException("Invalid client credentials"));

        if (!passwordEncoder.matches(clientSecret, client.getClientSecretHash())) {
            throw new BadCredentialsException("Invalid client credentials");
        }

        if (!client.getApplication().isActive()) {
            throw new BadCredentialsException("Invalid client credentials");
        }

        return client;
    }

    public ClientTokenResponse issueToken(String clientId, String clientSecret) {

        ApplicationClient client = authenticate(clientId, clientSecret);

        String accessToken = jwtService.generateClientToken(client);

        long expiresIn = jwtService.getClientExpiration() / 1000;

        return new ClientTokenResponse(
                accessToken,
                "Bearer",
                expiresIn);
    }

}
