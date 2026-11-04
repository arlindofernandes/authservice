package com.auth.authservice.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.auth.authservice.entity.Application;
import com.auth.authservice.entity.ApplicationClient;
import com.auth.authservice.repository.ApplicationClientRepository;

@ExtendWith(MockitoExtension.class)
class ApplicationClientServiceTest {

    @Mock
    private ApplicationClientRepository applicationClientRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private ApplicationClientService applicationClientService;

    @Test
    void shouldAuthenticateValidClient() {
        Application application = new Application();
        application.setActive(true);

        ApplicationClient client = new ApplicationClient();
        client.setClientId("test-client");
        client.setClientSecretHash("hashed-secret");
        client.setApplication(application);

        when(applicationClientRepository.findByClientIdAndActiveTrue("test-client"))
                .thenReturn(Optional.of(client));

        when(passwordEncoder.matches("secret", "hashed-secret"))
                .thenReturn(true);

        ApplicationClient result = applicationClientService.authenticate(
                "test-client", "secret");

        assertNotNull(result);
        assertEquals("test-client", result.getClientId());
    }

    @Test
    void shouldRejectInvalidSecret() {
        ApplicationClient client = new ApplicationClient();
        client.setClientSecretHash("hashed-secret");

        when(applicationClientRepository.findByClientIdAndActiveTrue("test-client"))
                .thenReturn(Optional.of(client));

        when(passwordEncoder.matches("wrong-secret", "hashed-secret"))
                .thenReturn(false);

        assertThrows(BadCredentialsException.class,
                () -> applicationClientService.authenticate(
                        "test-client", "wrong-secret"));
    }

    @Test
    void shouldRejectInactiveApplication() {
        Application application = new Application();
        application.setActive(false);

        ApplicationClient client = new ApplicationClient();
        client.setClientSecretHash("hashed-secret");
        client.setApplication(application);

        when(applicationClientRepository.findByClientIdAndActiveTrue("test-client"))
                .thenReturn(Optional.of(client));

        when(passwordEncoder.matches("secret", "hashed-secret"))
                .thenReturn(true);

        assertThrows(BadCredentialsException.class,
                () -> applicationClientService.authenticate(
                        "test-client", "secret"));
    }

    @Test
    void shouldRejectUnknownClient() {
        when(applicationClientRepository.findByClientIdAndActiveTrue("unknown"))
                .thenReturn(Optional.empty());

        assertThrows(BadCredentialsException.class,
                () -> applicationClientService.authenticate(
                        "unknown", "secret"));
    }

    @Test
    void shouldRejectBlankCredentials() {
        assertThrows(BadCredentialsException.class,
                () -> applicationClientService.authenticate("", "secret"));

        assertThrows(BadCredentialsException.class,
                () -> applicationClientService.authenticate("test-client", ""));

        verifyNoInteractions(applicationClientRepository);
    }
}