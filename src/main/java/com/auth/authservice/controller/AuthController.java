package com.auth.authservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.authservice.dto.AuthResponse;
import com.auth.authservice.dto.ClientTokenRequest;
import com.auth.authservice.dto.ClientTokenResponse;
import com.auth.authservice.dto.LoginRequest;
import com.auth.authservice.dto.RefreshRequest;
import com.auth.authservice.security.AuthPrincipal;
import com.auth.authservice.service.ApplicationClientService;
import com.auth.authservice.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final ApplicationClientService applicationClientService;

    public AuthController(AuthService authService, ApplicationClientService applicationClientService) {
        this.authService = authService;
        this.applicationClientService = applicationClientService;
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest request) {

        return authService.login(request);

    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@RequestBody RefreshRequest request) {
        return authService.refreshToken(request);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            HttpServletRequest request,
            @AuthenticationPrincipal AuthPrincipal principal) {

        authService.logout(request, principal);

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/client-token")
    public ClientTokenResponse clientToken(@Valid @RequestBody ClientTokenRequest request) {
        return applicationClientService.issueToken(
                request.clientId(),
                request.clientSecret());
    }

}