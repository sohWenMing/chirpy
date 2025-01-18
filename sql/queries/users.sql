-- name: CreateUser :one

INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    $1, $2, $3, $4, $5
)
RETURNING *;

-- name: DeleteUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT 
users.*
FROM users
WHERE users.email = $1
LIMIT 1;
