package com.auth.authservice.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.authservice.dto.MembershipRequestResponse;
import com.auth.authservice.security.TenantContext;
import com.auth.authservice.service.MembershipRequestService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@RequestMapping("/tenants/membership-requests")
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Tenant membership", description = "Administrative membership request operations")
@SecurityRequirement(name = "bearerAuth")
public class MembershipRequestController {
    private final MembershipRequestService membershipRequestService;

    public MembershipRequestController(MembershipRequestService membershipRequestService) {
        this.membershipRequestService = membershipRequestService;
    }

    @GetMapping
    @Operation(summary = "List pending membership requests for the current tenant")
    public List<MembershipRequestResponse> list() {
        return membershipRequestService.listForTenant(TenantContext.require());
    }

    @PostMapping("/{requestId}/approve")
    @Operation(summary = "Approve a pending membership request")
    public ResponseEntity<Void> approve(@PathVariable UUID requestId) {
        membershipRequestService.approve(requestId, TenantContext.require());
        return ResponseEntity.noContent().build();
    }
}
