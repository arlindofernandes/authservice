package com.auth.authservice.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.auth.authservice.entity.Application;

public interface ApplicationRepository extends JpaRepository<Application, UUID> {

    Optional<Application> findByAppKeyAndActiveTrue(String appKey);
}