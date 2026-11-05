package com.auth.authservice.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.auth.authservice.entity.MembershipApplication;

public interface MembershipApplicationRepository
                extends JpaRepository<MembershipApplication, UUID> {

        Optional<MembershipApplication> findByMembershipIdAndApplicationIdAndStatus(
                        UUID membershipId,
                        UUID applicationId,
                        MembershipApplication.Status status);

        @Query("""
                            SELECT ma
                            FROM MembershipApplication ma
                            JOIN FETCH ma.application
                            JOIN FETCH ma.membership m
                            JOIN FETCH m.tenant
                            JOIN FETCH m.user
                            JOIN FETCH ma.tenantApplication
                            WHERE ma.id = :id
                        """)
        Optional<MembershipApplication> findByIdWithAssociations(@Param("id") UUID id);
}