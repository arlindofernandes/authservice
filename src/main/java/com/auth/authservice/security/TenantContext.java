package com.auth.authservice.security;

import java.util.UUID;

public class TenantContext {

    private static final ThreadLocal<UUID> CURRENT_TENANT = new ThreadLocal<>();

    public static void set(UUID tenantId) {
        CURRENT_TENANT.set(tenantId);
    }

    public static UUID get() {
        return CURRENT_TENANT.get();
    }

    public static UUID require() {
        UUID tenantId = CURRENT_TENANT.get();
        if (tenantId == null) {
            throw new IllegalStateException("Tenant context is required for this operation");
        }
        return tenantId;
    }

    public static void clear() {
        CURRENT_TENANT.remove();
    }
}
