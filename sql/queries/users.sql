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

-- name: GetUserByUUID :one
SELECT users.*
 FROM users
 WHERE users.id = $1
LIMIT 1;

-- name: UpdateUser :one

UPDATE users
   SET email = $1,
       hashed_password = $2,
       updated_at = $3
WHERE id = $4
RETURNING *;


