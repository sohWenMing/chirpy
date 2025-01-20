-- +goose Up
AlTER TABLE users
ADD is_chirpy_red boolean DEFAULT false; 

-- +goose Down
ALTER TABLE users
DROP COLUMN is_chirpy_red; 