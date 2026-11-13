package com.auth.authservice.exception;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

class ApiExceptionHandlerTest {

    @Test
    void returnsAConflictResponseForDuplicateEmail() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/register");

        ResponseEntity<ApiError> response = new ApiExceptionHandler()
                .handleDuplicateEmail(new EmailAlreadyRegisteredException(), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody())
                .satisfies(error -> {
                    assertThat(error.status()).isEqualTo(409);
                    assertThat(error.error()).isEqualTo("Conflict");
                    assertThat(error.message()).isEqualTo("Email is already registered in this tenant");
                    assertThat(error.path()).isEqualTo("/auth/register");
                });
    }

    @Test
    void returnsAConflictResponseForDatabaseUniquenessViolations() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/register");

        ResponseEntity<ApiError> response = new ApiExceptionHandler()
                .handleDataIntegrityViolation(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);

        ApiError error = requireNonNull(response.getBody());

        assertThat(error.message())
                .isEqualTo("A record with these values already exists");
    }
}
