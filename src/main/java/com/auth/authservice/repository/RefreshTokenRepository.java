package com.auth.authservice.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.auth.authservice.entity.MembershipApplication;
import com.auth.authservice.entity.RefreshToken;

public interface RefreshTokenRepository
        extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findAllByMembershipApplicationAndRevokedFalse(
            MembershipApplication membershipApplication
    );
}