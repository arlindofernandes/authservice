-- 🔹 Criar tabela tenant
CREATE TABLE tenant (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        name VARCHAR(255) NOT NULL,
                        domain VARCHAR(255) NOT NULL UNIQUE
);

-- 🔹 Adicionar tenant_id
ALTER TABLE users
    ADD COLUMN tenant_id UUID NOT NULL;

ALTER TABLE refresh_token
    ADD COLUMN tenant_id UUID NOT NULL;

ALTER TABLE role ADD COLUMN tenant_id UUID;

-- 🔹 Foreign Keys
ALTER TABLE users
    ADD CONSTRAINT fk_users_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenant(id) ON DELETE CASCADE;

ALTER TABLE refresh_token
    ADD CONSTRAINT fk_refresh_token_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenant(id) ON DELETE CASCADE;

-- 🔥 INDEXES
CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_refresh_token_tenant ON refresh_token(tenant_id);
CREATE UNIQUE INDEX idx_refresh_token_token ON refresh_token(token);