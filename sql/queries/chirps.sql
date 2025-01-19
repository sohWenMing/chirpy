-- name: CreateChirp :one

INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    $1, $2, $3, $4, $5
)
RETURNING *;

-- name: GetChirps :many

SELECT * FROM chirps
 ORDER BY chirps.created_at ASC;

-- name: GetChirpById :one
 SELECT * FROM chirps
  WHERE chirps.id = $1;


-- name: DeleteChirpById :exec
 DELETE from chirps
 where chirps.id = $1;