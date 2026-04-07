package com.auth.authservice.repository;

import org.springframework.stereotype.Repository;

import com.auth.authservice.entity.Role;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {

    Optional<Role> findByName(String name);

}
