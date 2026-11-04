
package com.auth.authservice.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;

import com.auth.authservice.entity.MembershipApplication;
import com.auth.authservice.entity.RefreshToken;

public interface RefreshTokenRepository
                extends JpaRepository<RefreshToken, UUID> {

        @Lock(LockModeType.PESSIMISTIC_WRITE)
        @Query("SELECT rt FROM RefreshToken rt WHERE rt.token = :token")
        Optional<RefreshToken> findByTokenForUpdate(@Param("token") String token);

        List<RefreshToken> findAllByMembershipApplicationAndRevokedFalse(
                        MembershipApplication membershipApplication);

        List<RefreshToken> findAllBySessionIdAndRevokedFalse(UUID sessionId);
}
