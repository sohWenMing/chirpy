-- +goose Up

CREATE TABLE refresh_tokens (
    id text NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    user_id uuid NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    CONSTRAINT user_id_fk foreign key (user_id) references users(id) ON DELETE CASCADE
);

-- +goose Down
DROP TABLE refresh_tokens;
