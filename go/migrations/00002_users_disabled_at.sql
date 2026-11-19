-- +goose Up
-- null = active; set by an admin (SPEC 5, Disabling).
ALTER TABLE auth.users ADD COLUMN disabled_at timestamptz;

-- +goose Down
ALTER TABLE auth.users DROP COLUMN disabled_at;
