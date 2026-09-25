-- PostgreSQL persistence contract for the initial inventory vertical slice.
-- The runtime currently uses the in-memory Store until the PostgreSQL adapter is added.
CREATE TABLE agents (
  id text PRIMARY KEY, name text NOT NULL, hostname text NOT NULL,
  agent_version text NOT NULL, token_hash bytea NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'ACTIVE', last_seen_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE assets (
  id text PRIMARY KEY, agent_id text NOT NULL REFERENCES agents(id), hostname text NOT NULL,
  operating_system text NOT NULL, openssl_version text NOT NULL DEFAULT '', status text NOT NULL DEFAULT 'ONLINE',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE certificates (
  id text PRIMARY KEY, asset_id text NOT NULL REFERENCES assets(id), subject text NOT NULL, issuer text NOT NULL,
  serial_number text NOT NULL, fingerprint_sha256 text NOT NULL UNIQUE, public_key_algorithm text NOT NULL,
  public_key_bits integer NOT NULL, signature_algorithm text NOT NULL, not_before timestamptz NOT NULL, not_after timestamptz NOT NULL,
  self_signed boolean NOT NULL, certificate_path text NOT NULL, status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE certificate_sans (certificate_id text NOT NULL REFERENCES certificates(id) ON DELETE CASCADE, san_value text NOT NULL, PRIMARY KEY(certificate_id, san_value));
CREATE TABLE audit_events (id text PRIMARY KEY, event_type text NOT NULL, actor_id text NOT NULL, asset_id text, certificate_id text, severity text NOT NULL, message text NOT NULL, metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now());
REVOKE UPDATE, DELETE ON audit_events FROM PUBLIC;
