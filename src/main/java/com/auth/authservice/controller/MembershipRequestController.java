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

@RestController
@RequestMapping("/tenants/membership-requests")
@PreAuthorize("hasRole('ADMIN')")
public class MembershipRequestController {
    private final MembershipRequestService membershipRequestService;

    public MembershipRequestController(MembershipRequestService membershipRequestService) {
        this.membershipRequestService = membershipRequestService;
    }

    @GetMapping
    public List<MembershipRequestResponse> list() {
        return membershipRequestService.listForTenant(TenantContext.require());
    }

    @PostMapping("/{requestId}/approve")
    public ResponseEntity<Void> approve(@PathVariable UUID requestId) {
        membershipRequestService.approve(requestId, TenantContext.require());
        return ResponseEntity.noContent().build();
    }
}
