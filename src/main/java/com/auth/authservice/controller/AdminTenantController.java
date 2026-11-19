package com.auth.authservice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.auth.authservice.dto.AuthResponse;
import com.auth.authservice.dto.RegisterRequest;
import com.auth.authservice.service.AuthService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/admin/tenants")
@Tag(name = "Platform administration", description = "Platform-level tenant administration")
@SecurityRequirement(name = "platformAdminToken")
public class AdminTenantController {
    private final AuthService authService;

    public AdminTenantController(AuthService authService) { this.authService = authService; }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('PLATFORM_ADMIN')")
    @Operation(summary = "Create a tenant and its initial administrator")
    public AuthResponse registerTenant(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request);
    }
}
