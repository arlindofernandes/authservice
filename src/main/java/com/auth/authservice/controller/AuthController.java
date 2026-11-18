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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final MembershipRequestService membershipRequestService;

    public AuthController(AuthService authService, MembershipRequestService membershipRequestService) {
        this.authService = authService;
        this.membershipRequestService = membershipRequestService;
    }

    @PostMapping("/register")
    public AuthResponse register(
            @Valid @RequestBody RegisterRequest request) {

        return authService.register(request);
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) {

        return authService.login(request);

    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@Valid @RequestBody RefreshRequest request) {
        return authService.refreshToken(request);
    }

    @PostMapping("/membership-requests")
    public ResponseEntity<MembershipRequestResponse> requestMembership(
            @Valid @RequestBody MembershipRequestCreateRequest request) {
        return ResponseEntity.accepted().body(membershipRequestService.requestMembership(request));
    }

    @PostMapping("/logout")
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
