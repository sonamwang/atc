package main

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/adaptive-trust/atc/internal/agent"
	"github.com/adaptive-trust/atc/internal/config"
	"github.com/adaptive-trust/atc/internal/deployment"
	"github.com/adaptive-trust/atc/internal/issuer"
	"github.com/adaptive-trust/atc/internal/keys"
	"github.com/adaptive-trust/atc/internal/openssl"
	"github.com/adaptive-trust/atc/internal/renewal"
	"github.com/adaptive-trust/atc/internal/services"
	"github.com/adaptive-trust/atc/internal/storage"
	"github.com/adaptive-trust/atc/internal/transport"
)

func main() {
	server := flag.String("server", "http://127.0.0.1:8080", "ATC server URL")
	bootstrap := flag.String("bootstrap-token", os.Getenv("ATC_BOOTSTRAP_TOKEN"), "one-time enrollment credential")
	token := flag.String("agent-token", os.Getenv("ATC_AGENT_TOKEN"), "agent credential returned by enrollment")
	tokenFile := flag.String("token-file", "", "path for the agent credential (required for enrollment)")
	paths := flag.String("paths", "/etc/ssl,/etc/pki,/etc/nginx,/etc/apache2", "comma-separated certificate paths")
	configPath := flag.String("config", os.Getenv("ATC_AGENT_CONFIG"), "trusted agent YAML configuration file")
	executeRenewal := flag.String("execute-renewal", "", "explicit renewal job ID to execute using trusted agent configuration")
	executePending := flag.Bool("execute-pending", false, "continuously execute pending renewals using trusted agent configuration")
	pollInterval := flag.Duration("poll-interval", 5*time.Minute, "inventory and pending-renewal polling interval when -execute-pending is set")
	tlsCAFile := flag.String("tls-ca-file", os.Getenv("ATC_TLS_CA_FILE"), "PEM trust bundle for an HTTPS control plane")
	tlsCertificateFile := flag.String("tls-cert-file", os.Getenv("ATC_CLIENT_TLS_CERT_FILE"), "PEM client certificate for mutual TLS")
	tlsKeyFile := flag.String("tls-key-file", os.Getenv("ATC_CLIENT_TLS_KEY_FILE"), "PEM client private key for mutual TLS")
	flag.Parse()
	if err := transport.ValidateControlPlaneURL(*server); err != nil {
		fmt.Fprintln(os.Stderr, "invalid -server:", err)
		os.Exit(2)
	}
	if *executeRenewal != "" && *executePending {
		fmt.Fprintln(os.Stderr, "-execute-renewal and -execute-pending cannot be used together")
		os.Exit(2)
	}
	if *token == "" && *tokenFile != "" {
		stored, err := os.ReadFile(*tokenFile)
		if err == nil {
			*token = strings.TrimSpace(string(stored))
		}
	}
	if *bootstrap == "" && *token == "" {
		fmt.Fprintln(os.Stderr, "provide -bootstrap-token for enrollment or an existing -token-file")
		os.Exit(2)
	}
	host, _ := os.Hostname()
	client, err := transport.NewHTTPClient(*server, 15*time.Second, transport.ClientTLSConfig{CAFile: *tlsCAFile, CertificateFile: *tlsCertificateFile, KeyFile: *tlsKeyFile})
	if err != nil {
		fmt.Fprintln(os.Stderr, "configure control-plane TLS:", err)
		os.Exit(2)
	}
	if *token == "" {
		if *tokenFile == "" {
			fmt.Fprintln(os.Stderr, "-token-file is required for enrollment")
			os.Exit(2)
		}
		var err error
		*token, err = enroll(client, *server, *bootstrap, host)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := writeToken(*tokenFile, *token); err != nil {
			fmt.Fprintln(os.Stderr, "store agent token:", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "Enrollment succeeded; agent token stored with restrictive permissions")
	}
	scanPaths := strings.Split(*paths, ",")
	var trusted config.Agent
	if *configPath != "" {
		loaded, err := config.LoadAgent(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "load agent configuration:", err)
			os.Exit(2)
		}
		trusted = loaded
		if len(trusted.CertificatePaths) > 0 {
			scanPaths = trusted.CertificatePaths
		}
	}
	if (*executeRenewal != "" || *executePending) && *configPath == "" {
		fmt.Fprintln(os.Stderr, "renewal execution requires -config")
		os.Exit(2)
	}
	if *executePending {
		if *pollInterval <= 0 {
			fmt.Fprintln(os.Stderr, "-poll-interval must be positive")
			os.Exit(2)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		for {
			if err := uploadInventory(ctx, client, *server, *token, host, scanPaths, trusted.RenewalCertificateIDs()); err != nil {
				fmt.Fprintln(os.Stderr, "inventory cycle failed:", err)
			}
			if count, err := executePendingRenewals(ctx, client, *server, *token, trusted); err != nil {
				fmt.Fprintln(os.Stderr, "renewal poll failed:", err)
			} else if count > 0 {
				fmt.Printf("Processed %d pending renewal job(s)\n", count)
			}
			timer := time.NewTimer(*pollInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
	if err := uploadInventory(context.Background(), client, *server, *token, host, scanPaths, trusted.RenewalCertificateIDs()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *executeRenewal != "" {
		if err := executeOneRenewal(context.Background(), client, *server, *token, *executeRenewal, trusted); err != nil {
			fmt.Fprintln(os.Stderr, "renewal execution failed:", err)
			os.Exit(1)
		}
		fmt.Println("Renewal completed successfully")
	}
}

func uploadInventory(parent context.Context, client *http.Client, server, token, host string, scanPaths, renewableCertificateIDs []string) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	records, warnings := agent.Scan(ctx, scanPaths)
	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, "scan warning:", warning)
	}
	info, err := openssl.Discover(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "openssl warning:", err)
	}
	payload := map[string]any{"hostname": host, "operating_system": runtime.GOOS, "openssl_version": info.Version, "certificates": records, "renewable_certificate_ids": renewableCertificateIDs}
	if err := post(client, server+"/api/v1/inventory", token, payload, nil); err != nil {
		return err
	}
	fmt.Printf("Uploaded %d certificate records for %s\n", len(records), host)
	return nil
}

func executeOneRenewal(ctx context.Context, client *http.Client, server, token, jobID string, trusted config.Agent) error {
	commands, err := agent.FetchRenewals(ctx, server, token, client)
	if err != nil {
		return err
	}
	var commandFound bool
	var command storage.RenewalCommand
	for _, candidate := range commands {
		if candidate.Job.ID == jobID {
			command = candidate
			commandFound = true
			break
		}
	}
	if !commandFound {
		return fmt.Errorf("renewal job is not pending for this agent")
	}
	return executeRenewalCommand(ctx, client, server, token, command, trusted)
}

func executePendingRenewals(ctx context.Context, client *http.Client, server, token string, trusted config.Agent) (int, error) {
	commands, err := agent.FetchRenewals(ctx, server, token, client)
	if err != nil {
		return 0, err
	}
	completed := 0
	for _, command := range commands {
		if err := executeRenewalCommand(ctx, client, server, token, command, trusted); err != nil {
			fmt.Fprintln(os.Stderr, "pending renewal failed:", command.Job.ID, err)
			continue
		}
		completed++
	}
	return completed, nil
}

func executeRenewalCommand(ctx context.Context, client *http.Client, server, token string, command storage.RenewalCommand, trusted config.Agent) error {
	target, err := trusted.Resolve(command)
	if err != nil {
		return err
	}
	rotateKey := command.Job.RotateKey || target.RotateKey
	if !rotateKey && target.KeyID == "" {
		return fmt.Errorf("renewal target requires key_id when rotation is disabled")
	}
	var keyStore keys.KeyStore
	if trusted.KeyStore == "hardware_plugin" {
		keyStore, err = keys.NewHardwareKeyStore(trusted.HardwareSignerPlugin)
	} else {
		keyStore, err = keys.NewFileKeyStore(trusted.KeyDirectory)
	}
	if err != nil {
		return err
	}
	var deployer renewal.Stager
	if target.Deployment == "kubernetes_secret" {
		deployer, err = deployment.NewKubernetesSecretDeployer(deployment.KubernetesSecretConfig{
			Namespace:      target.Kubernetes.Namespace,
			Name:           target.Kubernetes.SecretName,
			CertificateKey: target.Kubernetes.CertificateKey,
			PrivateKey:     target.Kubernetes.PrivateKey,
		})
	} else {
		deployer, err = deployment.NewFileDeployer(trusted.DeploymentRoots)
	}
	if err != nil {
		return err
	}
	tlsValidator, err := services.NewTLSValidator(target.TLSAddress, target.TLSServerName, target.TLSCAFile)
	if err != nil {
		return err
	}
	remote := &agent.RenewalClient{ServerURL: server, Token: token, JobID: command.Job.ID, HTTPClient: client}
	var certificateIssuer issuer.CertificateIssuer = remote
	if target.Issuer == "acme_http01" {
		acmeIssuer, err := issuer.NewACMEHTTP01Issuer(issuer.ACMEHTTP01Config{
			DirectoryURL:           target.ACME.DirectoryURL,
			Email:                  target.ACME.Email,
			AccountKeyFile:         target.ACME.AccountKeyFile,
			Webroot:                target.ACME.Webroot,
			TermsOfServiceAccepted: target.ACME.TermsOfServiceAccepted,
		})
		if err != nil {
			return err
		}
		certificateIssuer = acmeIssuer
	}
	var service services.Provider
	if target.Service == "kubernetes" {
		service, err = services.NewKubernetesProvider(target.Kubernetes.Namespace, target.Kubernetes.Deployment)
	} else {
		service, err = services.NewProvider(target.Service)
	}
	if err != nil {
		return err
	}
	worker := renewal.NewWorker(keyStore, certificateIssuer, deployer, service).WithTLSValidator(tlsValidator)
	job := renewal.Job{KeyID: target.KeyID, CertificatePath: target.CertificatePath, KeyDeploymentPath: target.KeyDeploymentPath, KeyAlgorithm: target.KeyAlgorithm, RotateKey: rotateKey, Subject: pkix.Name{CommonName: target.CommonName}, DNSNames: target.DNSNames, Lifetime: 24 * time.Hour}
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return worker.Execute(runCtx, job, remote)
}

func writeToken(path, value string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("token directory is not a real directory")
	}
	if existing, err := os.Lstat(path); err == nil && existing.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace a symlinked token file")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".agent-token-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(value + "\n"); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	// Synchronize the rename when supported so a successful enrollment does not
	// report a token persisted before its directory entry is durable.
	directoryFile, err := os.Open(directory)
	if err == nil {
		defer directoryFile.Close()
		if err := directoryFile.Sync(); err != nil {
			return err
		}
	}
	return nil
}
func enroll(c *http.Client, server, bootstrap, host string) (string, error) {
	var response struct {
		AgentToken string `json:"agent_token"`
	}
	err := post(c, server+"/api/v1/agents/register", bootstrap, map[string]string{"name": "atc-agent", "hostname": host, "version": "0.1.0"}, &response)
	return response.AgentToken, err
}
func post(c *http.Client, url, token string, payload any, out any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	r, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	res, err := c.Do(r)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("server returned %s", res.Status)
	}
	if out != nil {
		return json.NewDecoder(res.Body).Decode(out)
	}
	return nil
}
