package storage

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adaptive-trust/atc/internal/certificates"
	"github.com/adaptive-trust/atc/internal/policy"
	"github.com/adaptive-trust/atc/internal/renewal"
	"github.com/adaptive-trust/atc/internal/retry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct{ pool *pgxpool.Pool }

func NewPostgres(ctx context.Context, databaseURL, migrationsDir string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect PostgreSQL: %w", err)
	}
	if err := applyMigrations(ctx, pool, migrationsDir); err != nil {
		pool.Close()
		return nil, err
	}
	return &Postgres{pool: pool}, nil
}

func applyMigrations(ctx context.Context, pool *pgxpool.Pool, dir string) error {
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sql") {
			continue
		}
		var applied bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, file.Name()).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", file.Name(), err)
		}
		if applied {
			continue
		}
		sql, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", file.Name(), err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", file.Name(), err)
		}
		if _, err = tx.Exec(ctx, string(sql)); err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, file.Name())
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", file.Name(), err)
		}
		if err = tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", file.Name(), err)
		}
	}
	return nil
}

func (p *Postgres) Close() { p.pool.Close() }
func (p *Postgres) Register(ctx context.Context, name, hostname, version string) (Agent, string, error) {
	if name == "" || hostname == "" {
		return Agent{}, "", errors.New("name and hostname are required")
	}
	raw, hash, err := token()
	if err != nil {
		return Agent{}, "", err
	}
	a := Agent{ID: id("agt"), Name: name, Hostname: hostname, Version: version, Status: "ACTIVE", LastSeen: time.Now().UTC()}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return Agent{}, "", err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO agents(id,name,hostname,agent_version,token_hash,last_seen_at) VALUES($1,$2,$3,$4,$5,$6)`, a.ID, a.Name, a.Hostname, a.Version, hash[:], a.LastSeen)
	if err != nil {
		return Agent{}, "", fmt.Errorf("insert agent: %w", err)
	}
	if err = insertAudit(ctx, tx, event("agent_registered", a.ID, "", "", "INFO", "Agent enrolled")); err != nil {
		return Agent{}, "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return Agent{}, "", err
	}
	return a, raw, nil
}
func (p *Postgres) Authenticate(ctx context.Context, raw string) (Agent, bool, error) {
	h := sha256.Sum256([]byte(raw))
	var a Agent
	err := p.pool.QueryRow(ctx, `SELECT id,name,hostname,agent_version,status,last_seen_at FROM agents WHERE token_hash=$1 AND status='ACTIVE'`, h[:]).Scan(&a.ID, &a.Name, &a.Hostname, &a.Version, &a.Status, &a.LastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return Agent{}, false, nil
	}
	if err != nil {
		return Agent{}, false, fmt.Errorf("authenticate agent: %w", err)
	}
	return a, true, nil
}
func (p *Postgres) RevokeAgent(ctx context.Context, agentID string, actor ...string) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	cmd, err := tx.Exec(ctx, `UPDATE agents SET status='REVOKED' WHERE id=$1 AND status='ACTIVE'`, agentID)
	if err != nil {
		return fmt.Errorf("revoke agent: %w", err)
	}
	if cmd.RowsAffected() == 1 {
		if err := insertAudit(ctx, tx, event("agent_revoked", auditActor(actor), "", "", "HIGH", "Agent credential revoked")); err != nil {
			return err
		}
	} else {
		var found bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE id=$1)`, agentID).Scan(&found); err != nil {
			return err
		}
		if !found {
			return errors.New("unknown agent")
		}
	}
	return tx.Commit(ctx)
}
func (p *Postgres) Ingest(ctx context.Context, agentID, hostname, osName, opensslVersion string, records []certificates.Record, renewableCertificateIDs []string, pol policy.Policy) (Asset, []Certificate, error) {
	if hostname == "" {
		return Asset{}, nil, errors.New("hostname is required")
	}
	now := time.Now().UTC()
	for index := range records {
		if records[index].ChainLength == 0 {
			records[index].ChainLength = 1
		}
		if records[index].DiscoveredAt.IsZero() {
			records[index].DiscoveredAt = now
		}
		if err := certificates.ValidateRecord(records[index]); err != nil {
			return Asset{}, nil, err
		}
	}
	a := Asset{ID: "asset_" + agentID, AgentID: agentID, Hostname: hostname, OS: osName, OpenSSLVersion: opensslVersion, UpdatedAt: now}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return Asset{}, nil, err
	}
	defer tx.Rollback(ctx)
	cmd, err := tx.Exec(ctx, `UPDATE agents SET last_seen_at=$2 WHERE id=$1 AND status='ACTIVE'`, agentID, now)
	if err != nil {
		return Asset{}, nil, err
	}
	if cmd.RowsAffected() != 1 {
		return Asset{}, nil, errors.New("unknown agent")
	}
	_, err = tx.Exec(ctx, `INSERT INTO assets(id,agent_id,hostname,operating_system,openssl_version,updated_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO UPDATE SET hostname=EXCLUDED.hostname,operating_system=EXCLUDED.operating_system,openssl_version=EXCLUDED.openssl_version,status='ONLINE',updated_at=EXCLUDED.updated_at`, a.ID, a.AgentID, a.Hostname, a.OS, a.OpenSSLVersion, a.UpdatedAt)
	if err != nil {
		return Asset{}, nil, fmt.Errorf("upsert asset: %w", err)
	}
	certs := make([]Certificate, 0, len(records))
	eligible := make(map[string]struct{}, len(renewableCertificateIDs))
	for _, certificateID := range renewableCertificateIDs {
		eligible[certificateID] = struct{}{}
	}
	for _, r := range records {
		stableID := certificateID(a.ID, r.Path)
		_, autoRenewEligible := eligible[stableID]
		c := Certificate{ID: stableID, AssetID: a.ID, Record: r, Policy: pol.Evaluate(r.NotAfter, r.SignatureAlgorithm, r.PublicKeyBits, now), AutoRenewEligible: autoRenewEligible, UpdatedAt: now}
		_, err = tx.Exec(ctx, `INSERT INTO certificates(id,asset_id,subject,issuer,serial_number,fingerprint_sha256,public_key_algorithm,public_key_bits,signature_algorithm,not_before,not_after,self_signed,certificate_path,status,key_usage,extended_key_usage,basic_constraints,chain_length,discovered_at,auto_renew_enabled,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) ON CONFLICT (id) DO UPDATE SET asset_id=EXCLUDED.asset_id,subject=EXCLUDED.subject,issuer=EXCLUDED.issuer,serial_number=EXCLUDED.serial_number,fingerprint_sha256=EXCLUDED.fingerprint_sha256,public_key_algorithm=EXCLUDED.public_key_algorithm,public_key_bits=EXCLUDED.public_key_bits,signature_algorithm=EXCLUDED.signature_algorithm,not_before=EXCLUDED.not_before,not_after=EXCLUDED.not_after,self_signed=EXCLUDED.self_signed,certificate_path=EXCLUDED.certificate_path,status=EXCLUDED.status,key_usage=EXCLUDED.key_usage,extended_key_usage=EXCLUDED.extended_key_usage,basic_constraints=EXCLUDED.basic_constraints,chain_length=EXCLUDED.chain_length,discovered_at=EXCLUDED.discovered_at,auto_renew_enabled=EXCLUDED.auto_renew_enabled,updated_at=EXCLUDED.updated_at`, c.ID, c.AssetID, r.Subject, r.Issuer, r.SerialNumber, r.FingerprintSHA256, r.PublicKeyAlgorithm, r.PublicKeyBits, r.SignatureAlgorithm, r.NotBefore, r.NotAfter, r.SelfSigned, r.Path, c.Policy.Status, r.KeyUsages, r.ExtendedKeyUsages, r.BasicConstraints, r.ChainLength, r.DiscoveredAt, c.AutoRenewEligible, c.UpdatedAt)
		if err != nil {
			return Asset{}, nil, fmt.Errorf("upsert certificate: %w", err)
		}
		if _, err = tx.Exec(ctx, `DELETE FROM certificate_sans WHERE certificate_id=$1`, c.ID); err != nil {
			return Asset{}, nil, err
		}
		for _, san := range r.SANs {
			if _, err = tx.Exec(ctx, `INSERT INTO certificate_sans(certificate_id,san_value) VALUES($1,$2)`, c.ID, san); err != nil {
				return Asset{}, nil, err
			}
		}
		if err = insertAudit(ctx, tx, event("certificate_discovered", agentID, a.ID, c.ID, c.Policy.Risk, c.Policy.Reason)); err != nil {
			return Asset{}, nil, err
		}
		certs = append(certs, c)
	}
	if err = insertAudit(ctx, tx, event("inventory_received", agentID, a.ID, "", "INFO", "Certificate inventory received")); err != nil {
		return Asset{}, nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Asset{}, nil, err
	}
	return a, certs, nil
}
func insertAudit(ctx context.Context, tx pgx.Tx, e AuditEvent) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,actor_id,asset_id,certificate_id,severity,message,created_at) VALUES($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,$7,$8)`, e.ID, e.EventType, e.ActorID, e.AssetID, e.CertificateID, e.Severity, e.Message, e.CreatedAt)
	return err
}
func (p *Postgres) Agents(ctx context.Context) ([]Agent, error) {
	rows, err := p.pool.Query(ctx, `SELECT id,name,hostname,agent_version,status,last_seen_at FROM agents ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Agent{}
	for rows.Next() {
		var a Agent
		if err = rows.Scan(&a.ID, &a.Name, &a.Hostname, &a.Version, &a.Status, &a.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (p *Postgres) Assets(ctx context.Context) ([]Asset, error) {
	rows, err := p.pool.Query(ctx, `SELECT id,agent_id,hostname,operating_system,openssl_version,updated_at FROM assets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Asset{}
	for rows.Next() {
		var a Asset
		if err = rows.Scan(&a.ID, &a.AgentID, &a.Hostname, &a.OS, &a.OpenSSLVersion, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (p *Postgres) Certificates(ctx context.Context) ([]Certificate, error) {
	rows, err := p.pool.Query(ctx, `SELECT c.id,c.asset_id,c.subject,c.issuer,c.serial_number,c.not_before,c.not_after,c.signature_algorithm,c.public_key_algorithm,c.public_key_bits,c.fingerprint_sha256,c.self_signed,c.certificate_path,c.key_usage,c.extended_key_usage,c.basic_constraints,c.chain_length,c.discovered_at,c.status,c.auto_renew_enabled,c.updated_at,COALESCE(array_agg(s.san_value) FILTER (WHERE s.san_value IS NOT NULL),'{}') FROM certificates c LEFT JOIN certificate_sans s ON s.certificate_id=c.id GROUP BY c.id ORDER BY c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Certificate{}
	now := time.Now().UTC()
	for rows.Next() {
		var c Certificate
		if err = rows.Scan(&c.ID, &c.AssetID, &c.Record.Subject, &c.Record.Issuer, &c.Record.SerialNumber, &c.Record.NotBefore, &c.Record.NotAfter, &c.Record.SignatureAlgorithm, &c.Record.PublicKeyAlgorithm, &c.Record.PublicKeyBits, &c.Record.FingerprintSHA256, &c.Record.SelfSigned, &c.Record.Path, &c.Record.KeyUsages, &c.Record.ExtendedKeyUsages, &c.Record.BasicConstraints, &c.Record.ChainLength, &c.Record.DiscoveredAt, &c.Policy.Status, &c.AutoRenewEligible, &c.UpdatedAt, &c.Record.SANs); err != nil {
			return nil, err
		}
		out = append(out, currentPolicy(c, now))
	}
	return out, rows.Err()
}
func (p *Postgres) Certificate(ctx context.Context, certificateID string) (Certificate, bool, error) {
	var c Certificate
	err := p.pool.QueryRow(ctx, `SELECT c.id,c.asset_id,c.subject,c.issuer,c.serial_number,c.not_before,c.not_after,c.signature_algorithm,c.public_key_algorithm,c.public_key_bits,c.fingerprint_sha256,c.self_signed,c.certificate_path,c.key_usage,c.extended_key_usage,c.basic_constraints,c.chain_length,c.discovered_at,c.status,c.auto_renew_enabled,c.updated_at,COALESCE(array_agg(s.san_value) FILTER (WHERE s.san_value IS NOT NULL),'{}') FROM certificates c LEFT JOIN certificate_sans s ON s.certificate_id=c.id WHERE c.id=$1 GROUP BY c.id`, certificateID).Scan(&c.ID, &c.AssetID, &c.Record.Subject, &c.Record.Issuer, &c.Record.SerialNumber, &c.Record.NotBefore, &c.Record.NotAfter, &c.Record.SignatureAlgorithm, &c.Record.PublicKeyAlgorithm, &c.Record.PublicKeyBits, &c.Record.FingerprintSHA256, &c.Record.SelfSigned, &c.Record.Path, &c.Record.KeyUsages, &c.Record.ExtendedKeyUsages, &c.Record.BasicConstraints, &c.Record.ChainLength, &c.Record.DiscoveredAt, &c.Policy.Status, &c.AutoRenewEligible, &c.UpdatedAt, &c.Record.SANs)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, false, nil
	}
	if err != nil {
		return Certificate{}, false, err
	}
	return currentPolicy(c, time.Now().UTC()), true, nil
}
func (p *Postgres) Audit(ctx context.Context) ([]AuditEvent, error) {
	rows, err := p.pool.Query(ctx, `SELECT id,event_type,actor_id,COALESCE(asset_id,''),COALESCE(certificate_id,''),severity,message,created_at FROM audit_events ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		if err = rows.Scan(&e.ID, &e.EventType, &e.ActorID, &e.AssetID, &e.CertificateID, &e.Severity, &e.Message, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *Postgres) RequestRenewal(ctx context.Context, certificateID, idempotencyKey string, rotateKey bool, actor ...string) (RenewalJob, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return RenewalJob{}, err
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM certificates WHERE id=$1)`, certificateID).Scan(&exists); err != nil {
		return RenewalJob{}, err
	}
	if !exists {
		return RenewalJob{}, errors.New("unknown certificate")
	}
	job := RenewalJob{ID: id("renewal"), CertificateID: certificateID, IdempotencyKey: idempotencyKey, Status: "RENEWAL_PENDING", RotateKey: rotateKey, RequestedAt: time.Now().UTC()}
	err = tx.QueryRow(ctx, `INSERT INTO renewal_jobs(id,certificate_id,idempotency_key,status,rotate_key,requested_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (idempotency_key) DO UPDATE SET idempotency_key=EXCLUDED.idempotency_key RETURNING id,certificate_id,idempotency_key,status,rotate_key,requested_at`, job.ID, job.CertificateID, job.IdempotencyKey, job.Status, job.RotateKey, job.RequestedAt).Scan(&job.ID, &job.CertificateID, &job.IdempotencyKey, &job.Status, &job.RotateKey, &job.RequestedAt)
	if err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			return RenewalJob{}, errors.New("active renewal job already exists")
		}
		return RenewalJob{}, fmt.Errorf("create renewal job: %w", err)
	}
	if job.CertificateID != certificateID || job.RotateKey != rotateKey {
		return RenewalJob{}, errors.New("idempotency key was used for another request")
	}
	if err = insertAudit(ctx, tx, event("certificate_renewal_requested", auditActor(actor), "", certificateID, "INFO", "Certificate renewal requested")); err != nil {
		return RenewalJob{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return RenewalJob{}, err
	}
	return job, nil
}

func (p *Postgres) Renewals(ctx context.Context) ([]RenewalJob, error) {
	rows, err := p.pool.Query(ctx, `SELECT id,certificate_id,idempotency_key,status,rotate_key,requested_at,attempt_count,next_attempt_at FROM renewal_jobs ORDER BY requested_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RenewalJob{}
	for rows.Next() {
		var job RenewalJob
		if err = rows.Scan(&job.ID, &job.CertificateID, &job.IdempotencyKey, &job.Status, &job.RotateKey, &job.RequestedAt, &job.AttemptCount, &job.NextAttemptAt); err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, rows.Err()
}

func (p *Postgres) PendingRenewals(ctx context.Context, agentID string) ([]RenewalCommand, error) {
	rows, err := p.pool.Query(ctx, `SELECT j.id,j.certificate_id,j.idempotency_key,j.status,j.rotate_key,j.requested_at,c.certificate_path,COALESCE(array_agg(s.san_value) FILTER (WHERE s.san_value IS NOT NULL),'{}') FROM renewal_jobs j JOIN certificates c ON c.id=j.certificate_id JOIN assets a ON a.id=c.asset_id LEFT JOIN certificate_sans s ON s.certificate_id=c.id WHERE a.agent_id=$1 AND j.status='RENEWAL_PENDING' GROUP BY j.id,c.certificate_path ORDER BY j.requested_at`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RenewalCommand{}
	for rows.Next() {
		var command RenewalCommand
		if err = rows.Scan(&command.Job.ID, &command.Job.CertificateID, &command.Job.IdempotencyKey, &command.Job.Status, &command.Job.RotateKey, &command.Job.RequestedAt, &command.CertificatePath, &command.DNSNames); err != nil {
			return nil, err
		}
		out = append(out, command)
	}
	return out, rows.Err()
}
func (p *Postgres) AdvanceRenewal(ctx context.Context, agentID, jobID string, from, to renewal.State) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var current string
	var assetID, certificateID string
	var attempts int
	err = tx.QueryRow(ctx, `SELECT j.status,a.id,c.id,j.attempt_count FROM renewal_jobs j JOIN certificates c ON c.id=j.certificate_id JOIN assets a ON a.id=c.asset_id WHERE j.id=$1 AND a.agent_id=$2 FOR UPDATE`, jobID, agentID).Scan(&current, &assetID, &certificateID, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("renewal job is not assigned to this agent")
	}
	if err != nil {
		return err
	}
	if current != string(from) {
		return errors.New("renewal state has changed")
	}
	if err = renewal.Transition(from, to); err != nil {
		return err
	}
	var nextAttempt *time.Time
	if to == renewal.RenewalFailed {
		attempts++
		if delay, delayErr := retry.Default().Delay(attempts, nil); delayErr == nil {
			value := time.Now().UTC().Add(delay)
			nextAttempt = &value
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE renewal_jobs SET status=$2,attempt_count=$3,next_attempt_at=$4,started_at=CASE WHEN $2='ISSUING' THEN now() ELSE started_at END,completed_at=CASE WHEN $2 IN ('ACTIVE','ROLLED_BACK','RENEWAL_FAILED') THEN now() ELSE completed_at END WHERE id=$1`, jobID, string(to), attempts, nextAttempt); err != nil {
		return err
	}
	if err = insertAudit(ctx, tx, event("renewal_state_changed", agentID, assetID, certificateID, "INFO", string(to))); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (p *Postgres) RequeueRenewals(ctx context.Context, now time.Time) (int, error) {
	cmd, err := p.pool.Exec(ctx, `WITH due AS (SELECT id FROM renewal_jobs WHERE status='RENEWAL_FAILED' AND next_attempt_at <= $1 AND attempt_count < $2 FOR UPDATE SKIP LOCKED) UPDATE renewal_jobs j SET status='RENEWAL_PENDING',next_attempt_at=NULL,completed_at=NULL FROM due WHERE j.id=due.id`, now, retry.Default().MaxAttempts)
	if err != nil {
		return 0, err
	}
	return int(cmd.RowsAffected()), nil
}
func (p *Postgres) EnqueueExpiringRenewals(ctx context.Context, now time.Time, policy policy.Policy) (int, error) {
	threshold := now.Add(time.Duration(policy.MediumDays) * 24 * time.Hour)
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT c.id,c.asset_id,c.updated_at,c.not_after,c.signature_algorithm,c.public_key_bits FROM certificates c WHERE c.auto_renew_enabled AND c.not_after < $1 AND NOT EXISTS (SELECT 1 FROM renewal_jobs j WHERE j.certificate_id=c.id AND j.requested_at >= c.updated_at) FOR UPDATE OF c SKIP LOCKED`, threshold)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	type candidate struct {
		certificateID, assetID, signature string
		updatedAt, notAfter               time.Time
		keyBits                           int
	}
	candidates := []candidate{}
	for rows.Next() {
		var candidate candidate
		if err := rows.Scan(&candidate.certificateID, &candidate.assetID, &candidate.updatedAt, &candidate.notAfter, &candidate.signature, &candidate.keyBits); err != nil {
			return 0, err
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	rows.Close()
	count := 0
	for _, candidate := range candidates {
		result := policy.Evaluate(candidate.notAfter, candidate.signature, candidate.keyBits, now)
		if result.Status != "EXPIRING" && result.Status != "EXPIRED" {
			continue
		}
		job := RenewalJob{ID: id("renewal"), CertificateID: candidate.certificateID, IdempotencyKey: "auto-" + candidate.certificateID + "-" + fmt.Sprint(candidate.updatedAt.Unix()), Status: "RENEWAL_PENDING", RequestedAt: now}
		command, err := tx.Exec(ctx, `INSERT INTO renewal_jobs(id,certificate_id,idempotency_key,status,rotate_key,requested_at) VALUES($1,$2,$3,$4,false,$5) ON CONFLICT DO NOTHING`, job.ID, job.CertificateID, job.IdempotencyKey, job.Status, job.RequestedAt)
		if err != nil {
			return 0, err
		}
		if command.RowsAffected() == 0 {
			continue
		}
		if err := insertAudit(ctx, tx, event("certificate_renewal_auto_requested", "scheduler", candidate.assetID, candidate.certificateID, result.Risk, result.Reason)); err != nil {
			return 0, err
		}
		count++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}
func (p *Postgres) AuthorizeRenewal(ctx context.Context, agentID, jobID string, expected renewal.State) error {
	var status string
	err := p.pool.QueryRow(ctx, `SELECT j.status FROM renewal_jobs j JOIN certificates c ON c.id=j.certificate_id JOIN assets a ON a.id=c.asset_id WHERE j.id=$1 AND a.agent_id=$2`, jobID, agentID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("renewal job is not assigned to this agent")
	}
	if err != nil {
		return err
	}
	if status != string(expected) {
		return errors.New("renewal state has changed")
	}
	return nil
}
