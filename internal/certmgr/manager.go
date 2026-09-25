// Package certmgr issues dynamically generated leaf certificates signed by a
// local root CA so that the MITM layer can terminate TLS for whitelisted hosts.
package certmgr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Manager loads (or creates) a root CA and derives per-host leaf certificates
// on demand. Leaf certificates are cached in memory.
type Manager struct {
	ca    *x509.Certificate
	caKey *rsa.PrivateKey
	cache sync.Map // host -> *tls.Certificate
}

// LoadOrCreate loads ca.crt/ca.key from dir. If either file is missing a new
// RSA-2048 root CA is generated and written to disk (key mode 0600).
func LoadOrCreate(dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create CA dir: %w", err)
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse existing CA: %w", err)
		}
		if len(cert.Certificate) == 0 {
			return nil, fmt.Errorf("existing CA has no certificates")
		}
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse existing CA certificate: %w", err)
		}
		key, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("existing CA key is not RSA")
		}
		return &Manager{ca: x509Cert, caKey: key}, nil
	}

	return generateAndStore(certPath, keyPath)
}

func generateAndStore(certPath, keyPath string) (*Manager, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "tlsdump Root CA", Organization: []string{"tlsdump"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign CA: %w", err)
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certOut, 0o644); err != nil {
		return nil, fmt.Errorf("write CA cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyOut, 0o600); err != nil {
		return nil, fmt.Errorf("write CA key: %w", err)
	}
	x509Cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated CA: %w", err)
	}
	return &Manager{ca: x509Cert, caKey: key}, nil
}

// GetCertificate implements tls.Config.GetCertificate. The leaf certificate
// is issued for hello.ServerName (SAN=dns) and cached per host.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.CertificateFor(hello.ServerName)
}

// CertificateFor issues (or returns a cached) leaf certificate for host.
// IP-literal hosts are placed in the IP SANs instead of DNS SANs.
func (m *Manager) CertificateFor(host string) (*tls.Certificate, error) {
	if host == "" {
		return nil, fmt.Errorf("no host for leaf certificate")
	}
	if v, ok := m.cache.Load(host); ok {
		return v.(*tls.Certificate), nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key for %s: %w", host, err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, 825),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{host},
		BasicConstraintsValid: true,
	}
	// IP literals cannot go into DNSNames; put them in IPAddresses instead.
	if ip := net.ParseIP(host); ip != nil {
		tmpl.DNSNames = nil
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.ca, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf for %s: %w", host, err)
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der, m.ca.Raw},
		PrivateKey:  key,
		Leaf:        tmpl,
	}
	m.cache.Store(host, cert)
	return cert, nil
}
