-- Adiciona o identificador de sessão aos refresh tokens.
ALTER TABLE refresh_token
    ADD COLUMN session_id UUID;

-- Preserva os registros existentes, atribuindo um identificador
-- individual a cada refresh token antigo.
UPDATE refresh_token
SET session_id = gen_random_uuid()
WHERE session_id IS NULL;

-- Torna o identificador obrigatório.
ALTER TABLE refresh_token
    ALTER COLUMN session_id SET NOT NULL;

-- Facilita a busca e revogação por sessão.
CREATE INDEX idx_refresh_token_session_id
    ON refresh_token(session_id);