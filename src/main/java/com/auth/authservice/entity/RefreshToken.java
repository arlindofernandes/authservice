package com.auth.authservice.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
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

    @ManyToOne
    private User user;
}
