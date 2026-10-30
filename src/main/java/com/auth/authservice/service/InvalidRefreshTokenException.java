package com.auth.authservice.service;

public class InvalidRefreshTokenException extends RuntimeException {

    public InvalidRefreshTokenException() {
        super("Invalid refresh token");
    }
}