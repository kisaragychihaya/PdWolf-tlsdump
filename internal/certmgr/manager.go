// Package certmgr issues dynamically generated leaf certificates signed by a
// local root CA so that the MITM layer can terminate TLS for whitelisted hosts.
package certmgr

import (
	"bytes"
	"crypto"
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
// on demand. Leaf certificates are cached in memory. An external CA can
// either cross-sign the local root (cross mode) or sign leaves directly
// (direct mode); in both cases clients that already trust the external CA
// accept the served chains without installing the local root.
type Manager struct {
	ca     *x509.Certificate
	caKey  *rsa.PrivateKey
	cross  *CrossIssuer // cross mode: serve leaf -> cross-signed root -> issuer
	direct *ExternalCA  // direct mode: leaves signed by the external CA key
	cache  sync.Map     // host -> *tls.Certificate
}

// ExternalCA is an external CA: the issuing intermediate certificate, its
// matching private key, and the DER chain served after the issued
// certificate (the issuer itself first, then any extra intermediates from
// the PEM file).
type ExternalCA struct {
	cert  *x509.Certificate
	key   crypto.PrivateKey
	chain [][]byte
}

// CrossIssuer is the cross-signing mode of an ExternalCA: the local root
// re-issued (cross-signed) by the external CA key.
type CrossIssuer struct {
	ext      *ExternalCA
	crossDER []byte // local root certificate, signed by ext.key
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

// loadExternalCA parses and validates an external CA (certificate chain +
// private key) shared by the cross-signing and direct-signing modes.
func loadExternalCA(certPEM, keyPEM []byte) (*ExternalCA, error) {
	issuer, chain, err := parseCertChain(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if !issuer.IsCA {
		return nil, fmt.Errorf("external CA %q is not a CA certificate", issuer.Subject)
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("external CA %q key usage does not allow signing certificates", issuer.Subject)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("external CA key does not implement crypto.Signer")
	}
	pubDER, err := x509.MarshalPKIXPublicKey(issuer.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal external CA public key: %w", err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal external CA key public key: %w", err)
	}
	if !bytes.Equal(pubDER, keyDER) {
		return nil, fmt.Errorf("external CA key does not match certificate %q", issuer.Subject)
	}
	return &ExternalCA{cert: issuer, key: key, chain: chain}, nil
}

// EnableCrossIssuer cross-signs the local root with the given external CA and
// makes the Manager serve leaf -> cross-signed root -> issuer chains from
// then on. certPEM must contain the issuing intermediate CA as its first PEM
// block; any further blocks are appended to the served chain. It returns the
// issuer's subject name for logging.
//
// Note: this mode adds one CA below the external intermediate, so the chain
// is rejected by path-length validation if that intermediate carries a
// pathlen constraint (e.g. pathlen:0, common in public Web PKI). Use
// EnableDirectSigner for such intermediates.
func (m *Manager) EnableCrossIssuer(certPEM, keyPEM []byte) (string, error) {
	ext, err := loadExternalCA(certPEM, keyPEM)
	if err != nil {
		return "", err
	}
	crossDER, err := m.buildCrossCertificate(ext.cert, ext.key)
	if err != nil {
		return "", err
	}
	m.cross = &CrossIssuer{ext: ext, crossDER: crossDER}
	m.direct = nil
	return ext.cert.Subject.String(), nil
}

// EnableDirectSigner makes the Manager sign leaf certificates directly with
// the given external CA (certificate chain + matching private key) and serve
// leaf -> issuer chains. Unlike cross mode, no extra CA sits below the
// external intermediate, so chains verify even when that intermediate has a
// pathlen:0 constraint. The local root is not part of the served chain.
func (m *Manager) EnableDirectSigner(certPEM, keyPEM []byte) (string, error) {
	ext, err := loadExternalCA(certPEM, keyPEM)
	if err != nil {
		return "", err
	}
	m.direct = ext
	m.cross = nil
	return ext.cert.Subject.String(), nil
}

// buildCrossCertificate re-issues the local root certificate, signed with the
// external CA key: same subject and subject public key as the local root, so
// existing leaf certificates link up via name + signature, but issued by the
// external CA. The validity is capped by the issuer's expiry.
func (m *Manager) buildCrossCertificate(issuer *x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("cross cert serial: %w", err)
	}
	notAfter := m.ca.NotAfter
	if issuer.NotAfter.Before(notAfter) {
		notAfter = issuer.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               m.ca.Subject,
		SubjectKeyId:          m.ca.SubjectKeyId,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &m.caKey.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("cross-sign root with %q: %w", issuer.Subject, err)
	}
	cross, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse cross certificate: %w", err)
	}
	// CreateCertificate re-encodes the parent's name from its parsed form; if
	// that differs from the original DER (non-canonical DN encoding), name
	// chaining breaks on clients, so fail fast instead of serving bad chains.
	if !bytes.Equal(cross.RawIssuer, issuer.RawSubject) {
		return nil, fmt.Errorf("cross issuer %q subject name re-encodes differently than the original certificate DER", issuer.Subject)
	}
	return der, nil
}

// parseCertChain decodes the first CERTIFICATE PEM block as the issuer and
// collects any additional blocks as extra chain certificates.
func parseCertChain(certPEM []byte) (*x509.Certificate, [][]byte, error) {
	var first *x509.Certificate
	var chain [][]byte
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse cross issuer certificate: %w", err)
		}
		if first == nil {
			first = cert
			continue
		}
		chain = append(chain, block.Bytes)
	}
	if first == nil {
		return nil, nil, fmt.Errorf("no CERTIFICATE block in cross issuer PEM")
	}
	return first, append([][]byte{first.Raw}, chain...), nil
}

// parsePrivateKey decodes a PEM private key in PKCS#8, PKCS#1 or SEC1 form.
// Non-key PEM blocks (e.g. the "EC PARAMETERS" block openssl ecparam writes
// ahead of the key) are skipped, so openssl-generated key files work as-is.
func parsePrivateKey(keyPEM []byte) (crypto.PrivateKey, error) {
	rest := keyPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("no PKCS#8, PKCS#1 or SEC1 private key found in cross key PEM")
		}
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
	}
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
	var (
		der   []byte
		chain [][]byte
	)
	switch {
	case m.direct != nil:
		// Leaves are signed by the external CA itself: leaf -> issuer (+ extras).
		der, err = x509.CreateCertificate(rand.Reader, tmpl, m.direct.cert, &key.PublicKey, m.direct.key)
		if err != nil {
			return nil, fmt.Errorf("sign leaf for %s: %w", host, err)
		}
		chain = append([][]byte{der}, m.direct.chain...)
	case m.cross != nil:
		der, err = x509.CreateCertificate(rand.Reader, tmpl, m.ca, &key.PublicKey, m.caKey)
		if err != nil {
			return nil, fmt.Errorf("sign leaf for %s: %w", host, err)
		}
		// leaf -> cross-signed root -> external issuer chain (+ extras);
		// the local root itself is not part of this path.
		chain = append([][]byte{der, m.cross.crossDER}, m.cross.ext.chain...)
	default:
		der, err = x509.CreateCertificate(rand.Reader, tmpl, m.ca, &key.PublicKey, m.caKey)
		if err != nil {
			return nil, fmt.Errorf("sign leaf for %s: %w", host, err)
		}
		chain = [][]byte{der, m.ca.Raw}
	}
	cert := &tls.Certificate{
		Certificate: chain,
		PrivateKey:  key,
		Leaf:        tmpl,
	}
	m.cache.Store(host, cert)
	return cert, nil
}
