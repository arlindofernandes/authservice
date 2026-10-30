package com.auth.authservice.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.auth.authservice.entity.TenantApplication;

public interface TenantApplicationRepository
        extends JpaRepository<TenantApplication, UUID> {

    Optional<TenantApplication> findByTenantIdAndApplicationIdAndStatus(
            UUID tenantId,
            UUID applicationId,
            TenantApplication.Status status
    );
}
