
-- Remove global email uniqueness
ALTER TABLE users
    DROP CONSTRAINT users_email_key;

-- Allow the same email in different tenants
ALTER TABLE users
    ADD CONSTRAINT uk_users_email_tenant
    UNIQUE (email, tenant_id);

-- Add tenant slug
ALTER TABLE tenant
    ADD COLUMN slug VARCHAR(255);

UPDATE tenant
SET slug = LOWER(
    REGEXP_REPLACE(
        TRIM(name),
        '[^a-zA-Z0-9]+',
        '-',
        'g'
    )
);

ALTER TABLE tenant
    ALTER COLUMN slug SET NOT NULL;

ALTER TABLE tenant
    ADD CONSTRAINT uk_tenant_slug UNIQUE (slug);

-- Domain is no longer globally unique
ALTER TABLE tenant
    DROP CONSTRAINT tenant_domain_key;
