package com.auth.authservice.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.auth.authservice.entity.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {

    Optional<Role> findByApplicationIdAndName(
            UUID applicationId,
            String name
    );

}
