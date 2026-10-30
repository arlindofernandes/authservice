package com.auth.authservice.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.auth.authservice.entity.TenantMembership;

public interface TenantMembershipRepository
        extends JpaRepository<TenantMembership, UUID> {

    Optional<TenantMembership> findByUserEmailAndTenantSlugAndStatus(
            String email,
            String slug,
            TenantMembership.Status status
    );
}
