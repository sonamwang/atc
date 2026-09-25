-- Preserve public X.509 properties required for certificate inspection and
-- audit evidence. These fields intentionally exclude all private-key data.
ALTER TABLE certificates
  ADD COLUMN key_usage text[] NOT NULL DEFAULT '{}',
  ADD COLUMN extended_key_usage text[] NOT NULL DEFAULT '{}',
  ADD COLUMN basic_constraints text NOT NULL DEFAULT '',
  ADD COLUMN chain_length integer NOT NULL DEFAULT 1 CHECK (chain_length >= 1 AND chain_length <= 100),
  ADD COLUMN discovered_at timestamptz NOT NULL DEFAULT now();
