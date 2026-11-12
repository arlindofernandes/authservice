package com.auth.authservice.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Setter
@Getter
public class RefreshToken {
    @Id
    @GeneratedValue
    private UUID id;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    private Instant expiryDate;

    private boolean revoked;

    private boolean used;

    @Column(nullable = false)
    private UUID tenantId;

    @ManyToOne
    private User user;
}
