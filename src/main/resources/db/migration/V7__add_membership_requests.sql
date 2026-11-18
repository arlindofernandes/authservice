CREATE TABLE membership_request (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    requested_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_membership_request_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenant(id) ON DELETE CASCADE,
    CONSTRAINT uk_membership_request_email_tenant UNIQUE (email, tenant_id)
);

CREATE INDEX idx_membership_request_tenant ON membership_request(tenant_id);
