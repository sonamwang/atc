-- Renewal state is separate from certificate material. Idempotency protects a
-- caller retry from creating competing deployment operations.
CREATE TABLE renewal_jobs (
  id text PRIMARY KEY,
  certificate_id text NOT NULL REFERENCES certificates(id),
  idempotency_key text NOT NULL UNIQUE,
  status text NOT NULL,
  rotate_key boolean NOT NULL DEFAULT false,
  requested_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  completed_at timestamptz,
  error_message text,
  attempt_count integer NOT NULL DEFAULT 0,
  new_certificate_id text
);
CREATE UNIQUE INDEX renewal_jobs_one_active_per_certificate
  ON renewal_jobs (certificate_id)
  WHERE status IN ('RENEWAL_PENDING', 'ISSUING', 'ISSUED', 'STAGED', 'VALIDATING');
