package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/adaptive-trust/atc/internal/api"
	"github.com/adaptive-trust/atc/internal/auth"
	"github.com/adaptive-trust/atc/internal/ct"
	"github.com/adaptive-trust/atc/internal/issuer"
	"github.com/adaptive-trust/atc/internal/notify"
	"github.com/adaptive-trust/atc/internal/policy"
	"github.com/adaptive-trust/atc/internal/risk"
	"github.com/adaptive-trust/atc/internal/storage"
	"github.com/adaptive-trust/atc/internal/transport"
)

func main() {
	addr := os.Getenv("ATC_SERVER_ADDRESS")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	bootstrap := os.Getenv("ATC_BOOTSTRAP_TOKEN")
	if bootstrap == "" {
		slog.Error("ATC_BOOTSTRAP_TOKEN must be configured")
		os.Exit(1)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var repo storage.Repository
	if os.Getenv("ATC_STORAGE") == "memory" {
		repo = storage.NewMemory()
		log.Warn("memory storage enabled; inventory will not survive a restart")
	} else {
		databaseURL := os.Getenv("ATC_DATABASE_URL")
		if databaseURL == "" {
			log.Error("ATC_DATABASE_URL must be configured unless ATC_STORAGE=memory")
			os.Exit(1)
		}
		migrationsDir := os.Getenv("ATC_MIGRATIONS_DIR")
		if migrationsDir == "" {
			migrationsDir = "migrations"
		}
		postgres, err := storage.NewPostgres(ctx, databaseURL, migrationsDir)
		if err != nil {
			log.Error("database initialization failed", "error", err)
			os.Exit(1)
		}
		repo = postgres
	}
	defer repo.Close()
	requireMTLS, err := envBool("ATC_REQUIRE_MTLS")
	if err != nil {
		log.Error("invalid ATC_REQUIRE_MTLS", "error", err)
		os.Exit(1)
	}
	autoRenew, err := envBool("ATC_AUTO_RENEW")
	if err != nil {
		log.Error("invalid ATC_AUTO_RENEW", "error", err)
		os.Exit(1)
	}
	certificatePolicy, err := policyFromEnvironment()
	if err != nil {
		log.Error("certificate policy initialization failed", "error", err)
		os.Exit(1)
	}
	tlsConfig, err := transport.LoadServerTLSConfig(transport.ServerTLSConfig{
		CertificateFile:   os.Getenv("ATC_TLS_CERT_FILE"),
		KeyFile:           os.Getenv("ATC_TLS_KEY_FILE"),
		ClientCAFile:      os.Getenv("ATC_TLS_CLIENT_CA_FILE"),
		RequireClientCert: requireMTLS,
	})
	if err != nil {
		log.Error("TLS initialization failed", "error", err)
		os.Exit(1)
	}
	if tlsConfig != nil {
		log.Info("TLS 1.3 enabled", "mutual_tls", tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert)
	}
	apiServer := api.New(repo, bootstrap, log)
	apiServer.WithPolicy(certificatePolicy)
	alertWebhook, err := alertWebhookFromConfig(os.Getenv("ATC_ALERT_WEBHOOK_URL"), os.Getenv("ATC_ALERT_WEBHOOK_SECRET"))
	if err != nil {
		log.Error("alert webhook initialization failed", "error", err)
		os.Exit(1)
	}
	if alertWebhook != nil {
		apiServer.WithNotifier(alertWebhook)
		log.Info("signed alert webhook enabled")
	}
	operatorCredentialsFile := os.Getenv("ATC_OPERATOR_CREDENTIALS_FILE")
	operatorToken := os.Getenv("ATC_OPERATOR_TOKEN")
	if operatorCredentialsFile != "" && operatorToken != "" {
		log.Error("configure either ATC_OPERATOR_CREDENTIALS_FILE or legacy ATC_OPERATOR_TOKEN, not both")
		os.Exit(1)
	}
	if operatorCredentialsFile != "" {
		authorizer, err := auth.LoadOperatorAuthorizer(operatorCredentialsFile)
		if err != nil {
			log.Error("operator RBAC initialization failed", "error", err)
			os.Exit(1)
		}
		apiServer.WithOperatorAuthorizer(authorizer)
		log.Info("multi-user operator RBAC enabled")
	} else if operatorToken != "" {
		apiServer.WithOperatorToken(operatorToken)
		log.Warn("legacy single operator token enabled; configure ATC_OPERATOR_CREDENTIALS_FILE for RBAC")
	} else {
		log.Warn("operator API authorization is disabled; local development only")
	}
	if rulesFile := os.Getenv("ATC_VULNERABILITY_RULES_FILE"); rulesFile != "" {
		rules, err := risk.LoadRules(rulesFile)
		if err != nil {
			log.Error("vulnerability rule initialization failed", "error", err)
			os.Exit(1)
		}
		apiServer.WithVulnerabilityRules(rules)
		log.Info("vulnerability rules enabled", "count", len(rules))
	}
	if endpoint := os.Getenv("ATC_CT_MONITOR_URL"); endpoint != "" {
		monitor, err := ct.NewMonitor(endpoint)
		if err != nil {
			log.Error("CT monitor initialization failed", "error", err)
			os.Exit(1)
		}
		apiServer.WithCTMonitor(monitor)
		log.Info("Certificate Transparency monitor enabled")
	}
	devCADir := os.Getenv("ATC_DEV_CA_DIR")
	issuerURL := os.Getenv("ATC_ISSUER_URL")
	if devCADir != "" && issuerURL != "" {
		log.Error("configure either ATC_DEV_CA_DIR or ATC_ISSUER_URL, not both")
		os.Exit(1)
	}
	if issuerURL != "" {
		productionIssuer, err := issuer.NewHTTPSIssuer(issuerURL, transport.ClientTLSConfig{
			CAFile:          os.Getenv("ATC_ISSUER_CA_FILE"),
			CertificateFile: os.Getenv("ATC_ISSUER_CLIENT_CERT_FILE"),
			KeyFile:         os.Getenv("ATC_ISSUER_CLIENT_KEY_FILE"),
		})
		if err != nil {
			log.Error("HTTPS issuer initialization failed", "error", err)
			os.Exit(1)
		}
		apiServer.WithIssuer(productionIssuer)
		log.Info("HTTPS CSR issuer enabled")
	} else if devCADir != "" {
		devCA, err := issuer.OpenDevelopmentCA(devCADir)
		if err != nil {
			log.Error("development CA initialization failed", "error", err)
			os.Exit(1)
		}
		apiServer.WithIssuer(devCA)
		log.Warn("development CA issuer enabled; never use this in production")
	}
	server := &http.Server{Addr: addr, Handler: apiServer.Handler(), ReadHeaderTimeout: 5 * time.Second, TLSConfig: tlsConfig}
	log.Info("atc server starting", "address", addr)
	go retryLoop(ctx, repo, log)
	if autoRenew {
		log.Warn("automatic renewal job creation enabled")
		go autoRenewLoop(ctx, repo, log, certificatePolicy)
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	var serveErr error
	if tlsConfig != nil {
		listener, err := tls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			serveErr = err
		} else {
			serveErr = server.Serve(listener)
		}
	} else {
		serveErr = server.ListenAndServe()
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		log.Error("atc server stopped", "error", serveErr)
		os.Exit(1)
	}
}

func alertWebhookFromConfig(endpoint, secret string) (notify.Notifier, error) {
	if (endpoint == "") != (secret == "") {
		return nil, fmt.Errorf("ATC_ALERT_WEBHOOK_URL and ATC_ALERT_WEBHOOK_SECRET must be configured together")
	}
	if endpoint == "" {
		return nil, nil
	}
	return notify.NewWebhook(endpoint, secret)
}

func envBool(name string) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, err
	}
	return parsed, nil
}

func policyFromEnvironment() (policy.Policy, error) {
	configured := policy.Default()
	for _, setting := range []struct {
		name  string
		value *int
	}{
		{"ATC_POLICY_CRITICAL_HOURS", &configured.CriticalHours},
		{"ATC_POLICY_HIGH_DAYS", &configured.HighDays},
		{"ATC_POLICY_MEDIUM_DAYS", &configured.MediumDays},
	} {
		raw := os.Getenv(setting.name)
		if raw == "" {
			continue
		}
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return policy.Policy{}, fmt.Errorf("%s must be an integer: %w", setting.name, err)
		}
		*setting.value = parsed
	}
	if err := configured.Validate(); err != nil {
		return policy.Policy{}, err
	}
	return configured, nil
}

func retryLoop(ctx context.Context, repo storage.Repository, log *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			count, err := repo.RequeueRenewals(ctx, now)
			if err != nil {
				log.Error("renewal retry scheduler failed", "error", err)
				continue
			}
			if count > 0 {
				log.Info("renewal jobs requeued", "count", count)
			}
		}
	}
}
func autoRenewLoop(ctx context.Context, repo storage.Repository, log *slog.Logger, certificatePolicy policy.Policy) {
	run := func() {
		count, err := repo.EnqueueExpiringRenewals(ctx, time.Now().UTC(), certificatePolicy)
		if err != nil {
			log.Error("automatic renewal scheduler failed", "error", err)
			return
		}
		if count > 0 {
			log.Info("automatic renewal jobs queued", "count", count)
		}
	}
	run()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
