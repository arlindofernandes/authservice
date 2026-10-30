package com.auth.authservice.repository;

import com.auth.authservice.entity.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface TenantRepository extends JpaRepository<Tenant, UUID> {
    Optional<Tenant> findBySlugAndActiveTrue(String slug);

    boolean existsBySlug(String slug);
}