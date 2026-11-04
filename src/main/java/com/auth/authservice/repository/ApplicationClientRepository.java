
package com.auth.authservice.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.auth.authservice.entity.ApplicationClient;

public interface ApplicationClientRepository
        extends JpaRepository<ApplicationClient, UUID> {

    Optional<ApplicationClient> findByClientIdAndActiveTrue(String clientId);
}
