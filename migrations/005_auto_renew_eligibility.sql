-- An agent may opt in individual stable certificate IDs for server-side
-- automatic job creation without disclosing deployment paths or key details.
ALTER TABLE certificates ADD COLUMN auto_renew_enabled boolean NOT NULL DEFAULT false;
CREATE INDEX certificates_auto_renew_expiry ON certificates(not_after) WHERE auto_renew_enabled;
