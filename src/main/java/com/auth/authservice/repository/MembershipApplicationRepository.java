package com.auth.authservice.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.auth.authservice.entity.MembershipApplication;

public interface MembershipApplicationRepository
        extends JpaRepository<MembershipApplication, UUID> {

    Optional<MembershipApplication> findByMembershipIdAndApplicationIdAndStatus(
            UUID membershipId,
            UUID applicationId,
            MembershipApplication.Status status
    );
}