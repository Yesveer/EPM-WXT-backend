package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	caValidity    = 365 * 24 * time.Hour
	caRotateAhead = 30 * 24 * time.Hour
	caGracePeriod = 7 * 24 * time.Hour

	serverValidity    = 30 * 24 * time.Hour
	serverRotateAhead = 7 * 24 * time.Hour

	// AgentCertValidity is exported so the sign-CSR handler can reference it.
	// 1-day validity: limits the window a stolen cert can be abused, and forces
	// daily key rotation which is best practice for short-lived mTLS credentials.
	AgentCertValidity = 24 * time.Hour
)

// gracedCA holds a superseded CA cert that is still trusted during the grace period.
type gracedCA struct {
	cert     *x509.Certificate
	removeAt time.Time
}

// CA manages the Private Certificate Authority for mTLS between server and agents.
type CA struct {
	mu       sync.RWMutex
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	certPEM  []byte
	certFile string
	keyFile  string
	prevCAs  []gracedCA
	logger   *zap.Logger
}

// LoadOrCreate loads an ECDSA P-256 CA from disk, or generates a new one.
// If an old RSA-based CA is found it is treated as unreadable and a fresh CA is generated.
func LoadOrCreate(certFile, keyFile string, logger *zap.Logger) (*CA, error) {
	if err := os.MkdirAll(filepath.Dir(certFile), 0750); err != nil {
		return nil, fmt.Errorf("create ca dir: %w", err)
	}

	ca := &CA{certFile: certFile, keyFile: keyFile, logger: logger}
	if err := ca.load(); err == nil {
		logger.Info("Loaded existing CA", zap.String("file", certFile),
			zap.String("valid_until", ca.cert.NotAfter.Format("2006-01-02")))
		return ca, nil
	}

	logger.Info("Generating new ECDSA P-256 CA (1-year validity)")
	if err := ca.generateLocked(); err != nil {
		return nil, err
	}
	return ca, nil
}

// load reads certFile+keyFile and populates ca.cert/key/certPEM.
func (ca *CA) load() error {
	certPEM, err := os.ReadFile(ca.certFile)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(ca.keyFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("decode key PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Old RSA key or other format — reject.
		return fmt.Errorf("parse EC key: %w", err)
	}

	ca.cert = cert
	ca.key = key
	ca.certPEM = certPEM
	return nil
}

// generateLocked creates a brand-new ECDSA P-256 CA and writes it to disk atomically.
// Must be called with ca.mu held (write) or before the CA is shared.
func (ca *CA) generateLocked() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Vsay"}, CommonName: "Vsay Agent CA"},
		NotBefore:             time.Now().Add(-10 * time.Second), // small back-date for clock skew
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := atomicWrite(ca.certFile, certPEM, 0644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	if err := atomicWrite(ca.keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}

	cert, _ := x509.ParseCertificate(certDER)
	ca.cert = cert
	ca.key = key
	ca.certPEM = certPEM
	ca.logger.Info("CA generated", zap.String("valid_until", tmpl.NotAfter.Format("2006-01-02")))
	return nil
}

// rotateLocked rotates the CA: moves current CA into prevCAs with a 7-day grace window,
// then generates a fresh CA. Must be called with ca.mu held (write).
func (ca *CA) rotateLocked() error {
	ca.logger.Warn("Rotating CA — old CA will remain trusted for grace period",
		zap.Duration("grace", caGracePeriod))

	// Stash current CA into grace list.
	ca.prevCAs = append(ca.prevCAs, gracedCA{
		cert:     ca.cert,
		removeAt: time.Now().Add(caGracePeriod),
	})

	// Prune expired grace CAs.
	ca.pruneGraceLocked()

	return ca.generateLocked()
}

// pruneGraceLocked removes grace CAs whose removeAt time has passed.
func (ca *CA) pruneGraceLocked() {
	now := time.Now()
	kept := ca.prevCAs[:0]
	for _, g := range ca.prevCAs {
		if now.Before(g.removeAt) {
			kept = append(kept, g)
		}
	}
	ca.prevCAs = kept
}

// CheckAndRotate checks whether the CA needs rotation and performs it if so.
// Returns true if rotation occurred. Safe to call from a goroutine.
func (ca *CA) CheckAndRotate() bool {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	ca.pruneGraceLocked()

	if time.Until(ca.cert.NotAfter) < caRotateAhead {
		if err := ca.rotateLocked(); err != nil {
			ca.logger.Error("CA rotation failed", zap.Error(err))
			return false
		}
		ca.logger.Info("CA rotated successfully")
		return true
	}
	return false
}

// RotationLoop runs CheckAndRotate every 12 hours in the background.
// After each rotation it regenerates the server cert and calls onRotate (if set)
// so the caller can broadcast the new CA cert to all connected agents.
func (ca *CA) RotationLoop(certFile, keyFile, domain string, onRotate func(newCAPEM []byte)) {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		rotated := ca.CheckAndRotate()
		if err := ca.EnsureServerCert(certFile, keyFile, domain); err != nil {
			ca.logger.Error("Server cert rotation failed", zap.Error(err))
		}
		if rotated && onRotate != nil {
			ca.mu.RLock()
			pem := ca.certPEM
			ca.mu.RUnlock()
			onRotate(pem)
		}
	}
}

// CertPool returns an x509.CertPool with the current CA cert plus any grace-period CAs.
func (ca *CA) CertPool() *x509.CertPool {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.certPoolLocked()
}

func (ca *CA) certPoolLocked() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	for _, g := range ca.prevCAs {
		pool.AddCert(g.cert)
	}
	return pool
}

// CertPEM returns the current CA certificate in PEM format.
func (ca *CA) CertPEM() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.certPEM
}

// Fingerprint returns the hex-encoded SHA-256 digest of the current CA cert DER bytes.
// Agents poll this to detect CA rotation.
func (ca *CA) Fingerprint() string {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	digest := sha256.Sum256(ca.cert.Raw)
	return hex.EncodeToString(digest[:])
}

// SignCSR signs a PEM-encoded CSR with a 5-day validity (AgentCertValidity).
func (ca *CA) SignCSR(csrPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}

	// Enforce ECDSA P-256 — reject weak keys (RSA, P-224, P-384 etc.) before signing.
	// An agent that sends a weak key would get a valid cert that is easy to break.
	ecKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("only ECDSA keys accepted, got %T", csr.PublicKey)
	}
	if ecKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("only ECDSA P-256 accepted, got curve %s", ecKey.Params().Name)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    now.Add(-10 * time.Second),
		NotAfter:     now.Add(AgentCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	ca.mu.RLock()
	caCert := ca.cert
	caKey := ca.key
	ca.mu.RUnlock()

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign cert: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

// EnsureServerCert generates (or regenerates) a server TLS cert signed by this CA.
// The cert is valid for 30 days and includes `domain` + "localhost" as SANs.
// It is a no-op if the existing cert still has > serverRotateAhead of life left
// AND was signed by the current CA.
func (ca *CA) EnsureServerCert(certFile, keyFile, domain string) error {
	// Check whether existing cert is still valid and signed by current CA.
	if existing, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		leaf, _ := x509.ParseCertificate(existing.Certificate[0])
		if leaf != nil && time.Until(leaf.NotAfter) > serverRotateAhead {
			ca.mu.RLock()
			pool := ca.certPoolLocked()
			ca.mu.RUnlock()
			opts := x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			if _, err := leaf.Verify(opts); err == nil {
				// Also check that the domain is in IPAddresses when it is an IP.
				// Old certs put the IP in DNSNames which Go TLS rejects on the client.
				if ip := net.ParseIP(domain); ip != nil {
					hasIPSAN := false
					for _, certIP := range leaf.IPAddresses {
						if certIP.Equal(ip) {
							hasIPSAN = true
							break
						}
					}
					if hasIPSAN {
						return nil // cert is fine, nothing to do
					}
					ca.logger.Info("Server cert missing IP SAN — regenerating", zap.String("domain", domain))
				} else {
					return nil // hostname cert is fine
				}
			}
		}
	}

	ca.logger.Info("Generating server TLS cert", zap.String("domain", domain),
		zap.Duration("validity", serverValidity))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()

	// Build SANs: always include both DNS and IP forms so the cert works
	// whether the client connects by hostname OR by IP address.
	// Go TLS requires IP addresses in IPAddresses (not DNSNames) for IP-based serverName.
	var dnsSANs []string
	var ipSANs []net.IP

	dnsSANs = append(dnsSANs, "localhost")
	ipSANs = append(ipSANs, net.IPv4(127, 0, 0, 1))

	if domain != "" && domain != "localhost" {
		if ip := net.ParseIP(domain); ip != nil {
			// IP domain: add to IPAddresses (required for Go TLS) AND to DNSNames
			// so tools that check only DNSNames also accept it.
			ipSANs = append(ipSANs, ip)
			dnsSANs = append(dnsSANs, domain)
		} else {
			dnsSANs = append([]string{domain}, dnsSANs...)
		}
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Vsay"}, CommonName: domain},
		NotBefore:    now.Add(-10 * time.Second),
		NotAfter:     now.Add(serverValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsSANs,
		IPAddresses:  ipSANs,
	}

	ca.mu.RLock()
	caCert := ca.cert
	caKey := ca.key
	ca.mu.RUnlock()

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create server cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(filepath.Dir(certFile), 0750); err != nil {
		return fmt.Errorf("create server cert dir: %w", err)
	}
	if err := atomicWrite(certFile, certPEM, 0644); err != nil {
		return fmt.Errorf("write server cert: %w", err)
	}
	if err := atomicWrite(keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("write server key: %w", err)
	}

	ca.logger.Info("Server cert written",
		zap.String("valid_until", tmpl.NotAfter.Format("2006-01-02")),
		zap.Strings("dns_sans", dnsSANs),
		zap.Any("ip_sans", ipSANs))
	return nil
}

// ServerTLSConfig returns a *tls.Config that uses GetConfigForClient to reload
// the server cert and CA pool on every incoming connection — enabling hot-reload
// after cert or CA rotation without a server restart.
func (ca *CA) ServerTLSConfig(certFile, keyFile string) *tls.Config {
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("load server cert: %w", err)
			}
			return &tls.Config{
				ClientAuth:   tls.RequireAndVerifyClientCert,
				Certificates: []tls.Certificate{cert},
				ClientCAs:    ca.CertPool(), // current + grace CAs
				MinVersion:   tls.VersionTLS13,
			}, nil
		},
		MinVersion: tls.VersionTLS13,
	}
}

// atomicWrite writes data to path by first writing to a temp file then renaming,
// so readers never see a partial file.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
