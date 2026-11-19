-- SPEC 3/5: null = active; set by an admin to disable the account (sessions are revoked in the same transaction).
ALTER TABLE "auth"."users" ADD COLUMN "disabled_at" TIMESTAMPTZ;
