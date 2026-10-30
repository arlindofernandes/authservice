package com.auth.authservice.service;

public class RefreshTokenReuseException extends RuntimeException {

    public RefreshTokenReuseException() {
        super("Refresh token reuse detected");
    }
}