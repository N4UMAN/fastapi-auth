CREATE EXTENSION IF NOT EXISTS pgcrypto;


CREATE TYPE token_type AS ENUM (
    'refresh',
    'email_verification',
    'password_reset'
)

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    token_type token_type NOT NULL,
    issued_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE
);


CREATE INDEX idx_junk_tokens ON auth_tokens(expires_at, is_revoked)
WHERE is_revoked = TRUE OR expires_at < NOW();