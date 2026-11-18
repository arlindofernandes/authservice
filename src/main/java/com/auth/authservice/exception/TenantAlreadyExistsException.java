package com.auth.authservice.exception;

public class TenantAlreadyExistsException extends RuntimeException {

    public TenantAlreadyExistsException() {
        super("Tenant name is already in use. Existing tenants require an invitation to add members");
    }
}
