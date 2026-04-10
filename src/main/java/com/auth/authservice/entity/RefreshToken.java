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

    private String token;

    private Instant expiryDate;

    private boolean revoked;

    private boolean used;

    @Column(nullable = false)
    private UUID tenantId;

    @ManyToOne
    private User user;
}
