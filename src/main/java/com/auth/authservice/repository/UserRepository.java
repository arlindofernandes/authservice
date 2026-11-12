package com.auth.authservice.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.repository.Repository;

import com.auth.authservice.entity.User;

public interface UserRepository extends Repository<User, UUID> {

    User save(User user);

    Optional<User> findByEmailAndTenantId(String email, UUID tenantId);

}
