-- +goose Up
CREATE TABLE chirps (
    id uuid PRIMARY KEY,
    created_at TIMESTAMP NOT NULL, 
    updated_at  TIMESTAMP NOT NULL,
    body TEXT NOT NULL,
    user_id uuid NOT NULL,
    CONSTRAINT fk_user FOREIGN KEY (user_id) references users(id) ON DELETE CASCADE
);
-- +goose Down
DROP TABLE chirps;