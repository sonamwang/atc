ALTER TABLE renewal_jobs ADD COLUMN next_attempt_at timestamptz;
CREATE INDEX renewal_jobs_retry_due ON renewal_jobs(next_attempt_at) WHERE status = 'RENEWAL_FAILED';
