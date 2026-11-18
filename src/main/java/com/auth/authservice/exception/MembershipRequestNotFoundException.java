package com.auth.authservice.exception;

public class MembershipRequestNotFoundException extends RuntimeException {
    public MembershipRequestNotFoundException() {
        super("Membership request not found");
    }
}
