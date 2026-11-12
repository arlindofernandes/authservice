package com.auth.authservice.repository;

import com.auth.authservice.entity.RefreshToken;
import com.auth.authservice.entity.User;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository
        extends Repository<RefreshToken, UUID> {

    <S extends RefreshToken> S save(S token);

    <S extends RefreshToken> List<S> saveAll(Iterable<S> tokens);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select token from RefreshToken token join fetch token.user where token.tokenHash = :tokenHash")
    Optional<RefreshToken> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    List<RefreshToken> findAllByUserAndRevokedFalse(User user);

}
