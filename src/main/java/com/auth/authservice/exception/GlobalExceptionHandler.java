package com.auth.authservice.exception;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.auth.authservice.service.InvalidRefreshTokenException;
import com.auth.authservice.service.RefreshTokenReuseException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(RefreshTokenReuseException.class)
    public ResponseEntity<Map<String, String>> handleRefreshTokenReuse(
            RefreshTokenReuseException exception) {

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Invalid refresh token"));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, String>> handleBadCredentials(
            BadCredentialsException exception) {

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Invalid credentials"));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidation(
            MethodArgumentNotValidException exception) {

        return ResponseEntity.badRequest()
                .body(Map.of("message", "Invalid request data"));
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<Map<String, String>> handleInvalidRefreshToken(
            InvalidRefreshTokenException exception) {

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Invalid refresh token"));
    }
}