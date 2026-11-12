package com.auth.authservice.exception;

public class DomainNotAllowedException extends RuntimeException {

    public DomainNotAllowedException() {
        super("Email domain is not allowed for this tenant");
    }
}
