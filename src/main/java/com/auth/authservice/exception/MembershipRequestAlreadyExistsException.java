package com.auth.authservice.exception;

public class MembershipRequestAlreadyExistsException extends RuntimeException {
    public MembershipRequestAlreadyExistsException() {
        super("A membership request already exists for this email in this tenant");
    }
}
