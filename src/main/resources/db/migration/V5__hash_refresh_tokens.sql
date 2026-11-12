UPDATE refresh_token
SET token = encode(digest(token, 'sha256'), 'hex');

ALTER TABLE refresh_token
    RENAME COLUMN token TO token_hash;
