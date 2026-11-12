package com.auth.authservice.service;

public class RefreshTokenValidationException extends RuntimeException {

    public RefreshTokenValidationException(String message) {
        super(message);
    }
}
