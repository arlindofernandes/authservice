package com.auth.authservice.config;

import java.util.Base64;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;

@Configuration
@ConfigurationProperties(prefix = "jwt")
@Validated
public class JwtProperties {
    @NotBlank
    private String secret;

    @Positive
    private long expiration;

    @PostConstruct
    void validateSecret() {
        try {
            byte[] key = Base64.getDecoder().decode(secret);
            if (key.length < 32) {
                throw new IllegalStateException("JWT secret must contain at least 256 bits");
            }
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("JWT secret must be Base64 encoded", exception);
        }
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public long getExpiration() {
        return expiration;
    }

    public void setExpiration(long expiration) {
        this.expiration = expiration;
    }
}
