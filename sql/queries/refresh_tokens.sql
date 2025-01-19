-- name: CreateRefreshToken :one

INSERT INTO refresh_tokens (
    id, 
    created_at, 
    updated_at, 
    user_id,
    expires_at,
    revoked_at 
    )
VALUES (
    $1, $2, $3, $4, $5, $6
)
RETURNING *;


-- name: GetRefreshTokenById :one

SELECT refresh_tokens.id, refresh_tokens.user_id, refresh_tokens.expires_at, refresh_tokens.revoked_at
  FROM refresh_tokens
  WHERE refresh_tokens.id = $1
    AND refresh_tokens.expires_at IS NOT NULL
  LIMIT 1;


-- name: RevokeRefreshToken :exec

UPDATE refresh_tokens 
   SET updated_at = $2,
    revoked_at = $3
 WHERE id = $1;