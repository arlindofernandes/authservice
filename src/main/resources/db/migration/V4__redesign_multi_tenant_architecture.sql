
-- =========================================================
-- V4 - Redesign da arquitetura multi-tenant
-- ATENCAO: migration destrutiva para o banco local de testes.
-- As migrations V1, V2 e V3 permanecem inalteradas.
-- =========================================================

-- 1. Remover a estrutura anterior
DROP TABLE IF EXISTS refresh_token CASCADE;
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS role_permissions CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS role CASCADE;
DROP TABLE IF EXISTS permission CASCADE;
DROP TABLE IF EXISTS tenant CASCADE;

-- 2. Identidade
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(150) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- E-mail único sem diferenciar maiúsculas e minúsculas.
CREATE UNIQUE INDEX uq_users_email_lower
    ON users (LOWER(email));

-- 3. Tenants
CREATE TABLE tenant (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(150) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_tenant_slug UNIQUE (slug),
    CONSTRAINT ck_tenant_slug_format
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$')
);

-- 4. Associação entre usuários e tenants
CREATE TABLE tenant_membership (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_membership_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,

    CONSTRAINT fk_membership_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenant(id) ON DELETE CASCADE,

    CONSTRAINT uq_membership_user_tenant
        UNIQUE (user_id, tenant_id),

    CONSTRAINT uq_membership_id_tenant
        UNIQUE (id, tenant_id),

    CONSTRAINT ck_membership_status
        CHECK (status IN ('ACTIVE', 'INVITED', 'SUSPENDED'))
);

CREATE INDEX idx_membership_tenant
    ON tenant_membership(tenant_id);

CREATE INDEX idx_membership_user
    ON tenant_membership(user_id);

-- 5. Aplicações clientes do AuthService
CREATE TABLE application (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_key VARCHAR(80) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_application_key UNIQUE (app_key),
    CONSTRAINT uq_application_id_key UNIQUE (id, app_key)
);

-- 6. Credenciais de comunicação entre aplicações e AuthService
CREATE TABLE application_client (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL,
    client_id VARCHAR(150) NOT NULL,
    client_secret_hash VARCHAR(255) NOT NULL,
    name VARCHAR(150) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_application_client_application
        FOREIGN KEY (application_id)
        REFERENCES application(id) ON DELETE CASCADE,

    CONSTRAINT uq_application_client_id UNIQUE (client_id)
);

CREATE INDEX idx_application_client_application
    ON application_client(application_id);

-- 7. Aplicações habilitadas por tenant
CREATE TABLE tenant_application (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    application_id UUID NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_tenant_application_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenant(id) ON DELETE CASCADE,

    CONSTRAINT fk_tenant_application_application
        FOREIGN KEY (application_id) REFERENCES application(id) ON DELETE RESTRICT,

    CONSTRAINT uq_tenant_application
        UNIQUE (tenant_id, application_id),

    CONSTRAINT uq_tenant_application_id_tenant
        UNIQUE (id, tenant_id),

    CONSTRAINT uq_tenant_application_id_app
        UNIQUE (id, application_id),

    CONSTRAINT ck_tenant_application_status
        CHECK (status IN ('ACTIVE', 'SUSPENDED'))
);

-- 8. Acesso de uma membership a uma aplicação
CREATE TABLE membership_application (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    application_id UUID NOT NULL,
    membership_id UUID NOT NULL,
    tenant_application_id UUID NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_membership_application_membership
        FOREIGN KEY (membership_id, tenant_id)
        REFERENCES tenant_membership(id, tenant_id) ON DELETE CASCADE,

    CONSTRAINT fk_membership_application_tenant_app
        FOREIGN KEY (tenant_application_id, tenant_id)
        REFERENCES tenant_application(id, tenant_id) ON DELETE CASCADE,

    CONSTRAINT fk_membership_application_app
        FOREIGN KEY (tenant_application_id, application_id)
        REFERENCES tenant_application(id, application_id) ON DELETE CASCADE,

    CONSTRAINT uq_membership_application
        UNIQUE (membership_id, application_id),

    CONSTRAINT uq_membership_application_id_app
        UNIQUE (id, application_id),

    CONSTRAINT ck_membership_application_status
        CHECK (status IN ('ACTIVE', 'SUSPENDED'))
);

CREATE INDEX idx_membership_application_membership
    ON membership_application(membership_id);

-- 9. Papéis por aplicação
CREATE TABLE role (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(255),

    CONSTRAINT fk_role_application
        FOREIGN KEY (application_id)
        REFERENCES application(id) ON DELETE CASCADE,

    CONSTRAINT uq_role_application_name
        UNIQUE (application_id, name),

    CONSTRAINT uq_role_id_application
        UNIQUE (id, application_id)
);

-- 10. Permissões por aplicação
CREATE TABLE permission (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(255),

    CONSTRAINT fk_permission_application
        FOREIGN KEY (application_id)
        REFERENCES application(id) ON DELETE CASCADE,

    CONSTRAINT uq_permission_application_name
        UNIQUE (application_id, name),

    CONSTRAINT uq_permission_id_application
        UNIQUE (id, application_id)
);

-- 11. Permissões associadas aos papéis
CREATE TABLE role_permissions (
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    application_id UUID NOT NULL,

    PRIMARY KEY (role_id, permission_id),

    CONSTRAINT fk_role_permissions_role
        FOREIGN KEY (role_id, application_id)
        REFERENCES role(id, application_id) ON DELETE CASCADE,

    CONSTRAINT fk_role_permissions_permission
        FOREIGN KEY (permission_id, application_id)
        REFERENCES permission(id, application_id) ON DELETE CASCADE
);

-- 12. Papéis atribuídos ao usuário em uma aplicação
CREATE TABLE membership_application_roles (
    membership_application_id UUID NOT NULL,
    role_id UUID NOT NULL,
    application_id UUID NOT NULL,

    PRIMARY KEY (membership_application_id, role_id),

    CONSTRAINT fk_membership_application_roles_membership
        FOREIGN KEY (membership_application_id, application_id)
        REFERENCES membership_application(id, application_id) ON DELETE CASCADE,

    CONSTRAINT fk_membership_application_roles_role
        FOREIGN KEY (role_id, application_id)
        REFERENCES role(id, application_id) ON DELETE CASCADE
);

-- 13. Refresh tokens vinculados ao contexto de acesso
CREATE TABLE refresh_token (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    membership_application_id UUID NOT NULL,
    token VARCHAR(512) NOT NULL,
    expiry_date TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_refresh_token UNIQUE (token),

    CONSTRAINT fk_refresh_token_membership_application
        FOREIGN KEY (membership_application_id)
        REFERENCES membership_application(id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_token_membership_application
    ON refresh_token(membership_application_id);

-- 14. Aplicações iniciais
INSERT INTO application (app_key, name, description) VALUES
    ('tempora', 'Tempora', 'Sistema SaaS de agendamento'),
    ('cardwise', 'CardWise', 'Sistema de gerenciamento financeiro');

-- 15. Papéis e permissões iniciais para cada aplicação
INSERT INTO permission (application_id, name, description)
SELECT a.id, p.name, p.description
FROM application a
CROSS JOIN (
    VALUES
        ('USER_READ', 'Permite consultar recursos'),
        ('USER_WRITE', 'Permite criar e atualizar recursos'),
        ('USER_DELETE', 'Permite excluir recursos')
) AS p(name, description);

INSERT INTO role (application_id, name, description)
SELECT a.id, r.name, r.description
FROM application a
CROSS JOIN (
    VALUES
        ('USER', 'Usuário padrão'),
        ('ADMIN', 'Administrador da aplicação')
) AS r(name, description);

-- ADMIN recebe todas as permissões da aplicação.
INSERT INTO role_permissions (role_id, permission_id, application_id)
SELECT r.id, p.id, r.application_id
FROM role r
JOIN permission p
    ON p.application_id = r.application_id
WHERE r.name = 'ADMIN';

-- USER recebe apenas USER_READ inicialmente.
INSERT INTO role_permissions (role_id, permission_id, application_id)
SELECT r.id, p.id, r.application_id
FROM role r
JOIN permission p
    ON p.application_id = r.application_id
WHERE r.name = 'USER'
  AND p.name = 'USER_READ';
