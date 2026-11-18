package com.auth.authservice.controller;

import java.security.Principal;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.authservice.dto.AuthResponse;
import com.auth.authservice.dto.LoginRequest;
import com.auth.authservice.dto.MembershipRequestCreateRequest;
import com.auth.authservice.dto.MembershipRequestResponse;
import com.auth.authservice.dto.RefreshRequest;
import com.auth.authservice.dto.RegisterRequest;
import com.auth.authservice.security.TenantContext;
import com.auth.authservice.service.AuthService;
import com.auth.authservice.service.MembershipRequestService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication", description = "Registration, login, token refresh and logout")
public class AuthController {

    private final AuthService authService;
    private final MembershipRequestService membershipRequestService;

    public AuthController(AuthService authService, MembershipRequestService membershipRequestService) {
        this.authService = authService;
        this.membershipRequestService = membershipRequestService;
    }

    @PostMapping("/register")
    @Operation(summary = "Register a new tenant and its initial administrator")
    public AuthResponse register(
            @Valid @RequestBody RegisterRequest request) {

        return authService.register(request);
    }

    @PostMapping("/login")
    @Operation(summary = "Authenticate with tenant slug, email and password")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) {

        return authService.login(request);

    }

    @PostMapping("/refresh")
    @Operation(summary = "Rotate a refresh token and issue a new token pair")
    public AuthResponse refresh(@Valid @RequestBody RefreshRequest request) {
        return authService.refreshToken(request);
    }

    @PostMapping("/membership-requests")
    @Operation(summary = "Request membership in an existing tenant")
    public ResponseEntity<MembershipRequestResponse> requestMembership(
            @Valid @RequestBody MembershipRequestCreateRequest request) {
        return ResponseEntity.accepted().body(membershipRequestService.requestMembership(request));
    }

    @PostMapping("/logout")
    @Operation(summary = "Revoke the current access and refresh tokens")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<Void> logout(
            HttpServletRequest request,
            @Valid @RequestBody RefreshRequest refreshRequest,
            Principal principal) {

        UUID tenantId = TenantContext.require();

        authService.logout(
                request,
                principal.getName(),
                tenantId,
                refreshRequest);

        return ResponseEntity.noContent().build();
    }

}
