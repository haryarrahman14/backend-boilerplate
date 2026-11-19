-- null = active; set by an admin. Disabled accounts cannot log in, refresh or pass the auth guard.
ALTER TABLE auth.users ADD COLUMN disabled_at timestamptz;
