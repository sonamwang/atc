-- A certificate asset is identified by its owning asset and configured path,
-- not by its mutable fingerprint. A renewal therefore updates one inventory
-- record and retains the operator's trusted renewal-target mapping.
ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_fingerprint_sha256_key;
CREATE UNIQUE INDEX certificates_asset_path_unique ON certificates(asset_id, certificate_path);
CREATE INDEX certificates_fingerprint_sha256_index ON certificates(fingerprint_sha256);
