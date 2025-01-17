-- +goose Up
ALTER TABLE users
ADD hashed_password TEXT DEFAULT 'unset';

-- +goose Down
ALTER TABLE users
DROP hashed_password;
