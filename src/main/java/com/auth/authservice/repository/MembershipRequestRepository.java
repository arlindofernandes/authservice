package com.auth.authservice.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.auth.authservice.entity.MembershipRequest;

public interface MembershipRequestRepository extends JpaRepository<MembershipRequest, UUID> {
    boolean existsByEmailAndTenantId(String email, UUID tenantId);
    Optional<MembershipRequest> findByIdAndTenantId(UUID id, UUID tenantId);
    List<MembershipRequest> findAllByTenantIdOrderByRequestedAtAsc(UUID tenantId);
}
