package certmgr

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// makeToyHierarchy builds a stand-in for the "external CA" role: a self-signed
// root plus an intermediate CA issued by it (ECDSA P-384, mirroring the
// real-world structure of cross-signing setups), returned as parsed
// certificates plus PEM blobs. When pathlen0 is set, the intermediate gets a
// pathlen:0 basic constraint like public Web PKI intermediates.
func makeToyHierarchy(t *testing.T, pathlen0 bool) (root, inter *x509.Certificate, rootPEM, interPEM, interKeyPEM []byte) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	interKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Toy Root", Organization: []string{"Toy PKI"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Toy Intermediate", Organization: []string{"Toy PKI"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{5, 6, 7, 8},
	}
	if pathlen0 {
		interTmpl.MaxPathLenZero = true
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, err = x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(interKey)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	interPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})
	interKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return root, inter, rootPEM, interPEM, interKeyPEM
}

// verifyLeaf validates the served chain for host against the external root,
// the way a client that trusts only that root would.
func verifyLeaf(t *testing.T, certChain [][]byte, root *x509.Certificate, host string) error {
	t.Helper()
	leaf, err := x509.ParseCertificate(certChain[0])
	if err != nil {
		t.Fatal(err)
	}
	intermediates := x509.NewCertPool()
	for _, der := range certChain[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(c)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func TestEnableCrossIssuerChainVerifies(t *testing.T) {
	root, inter, _, interPEM, interKeyPEM := makeToyHierarchy(t, false)

	m, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	issuerName, err := m.EnableCrossIssuer(interPEM, interKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if issuerName != inter.Subject.String() {
		t.Errorf("issuer name = %q, want %q", issuerName, inter.Subject.String())
	}

	cert, err := m.CertificateFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 3 {
		t.Fatalf("chain length = %d, want 3 (leaf, cross, issuer)", len(cert.Certificate))
	}

	cross, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	if !cross.IsCA {
		t.Error("cross certificate is not a CA")
	}
	if cross.Subject.String() != m.ca.Subject.String() {
		t.Errorf("cross subject = %q, want local root subject %q", cross.Subject, m.ca.Subject)
	}
	if cross.Issuer.String() != inter.Subject.String() {
		t.Errorf("cross issuer = %q, want %q", cross.Issuer, inter.Subject)
	}
	if pub, ok := cross.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&m.caKey.PublicKey) {
		t.Error("cross certificate does not carry the local root public key")
	}
	if !bytes.Equal(cross.AuthorityKeyId, inter.SubjectKeyId) {
		t.Error("cross AKID does not reference the issuer SKID")
	}

	if err := verifyLeaf(t, cert.Certificate, root, "example.com"); err != nil {
		t.Fatalf("cross-signed chain did not verify against the external root: %v", err)
	}

	// Without the external root in the trust store the same chain must fail.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	intermediates := x509.NewCertPool()
	intermediates.AddCert(cross)
	intermediates.AddCert(inter)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: x509.NewCertPool(), Intermediates: intermediates}); err == nil {
		t.Fatal("chain verified with an empty root pool")
	}
}

// Cross-signing inserts one more CA below the external intermediate, so a
// pathlen:0 intermediate (the public Web PKI default, e.g. the compromised
// eMudhra intermediates) makes every compliant client reject the chain with a
// path length error. This is why EnableDirectSigner exists.
func TestEnableCrossIssuerUnderPathLenZeroRejected(t *testing.T) {
	root, _, _, interPEM, interKeyPEM := makeToyHierarchy(t, true)

	m, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.EnableCrossIssuer(interPEM, interKeyPEM); err != nil {
		t.Fatal(err)
	}
	cert, err := m.CertificateFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyLeaf(t, cert.Certificate, root, "example.com"); err == nil {
		t.Fatal("cross-signed chain verified under a pathlen:0 intermediate; want path length error")
	}
}

// Direct signing puts the leaf right under the external intermediate, so it
// verifies even when that intermediate carries pathlen:0.
func TestEnableDirectSignerPathLenZero(t *testing.T) {
	root, inter, _, interPEM, interKeyPEM := makeToyHierarchy(t, true)

	m, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	issuerName, err := m.EnableDirectSigner(interPEM, interKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if issuerName != inter.Subject.String() {
		t.Errorf("issuer name = %q, want %q", issuerName, inter.Subject.String())
	}

	cert, err := m.CertificateFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("chain length = %d, want 2 (leaf, issuer)", len(cert.Certificate))
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Issuer.String() != inter.Subject.String() {
		t.Errorf("leaf issuer = %q, want %q", leaf.Issuer, inter.Subject)
	}
	if !bytes.Equal(leaf.AuthorityKeyId, inter.SubjectKeyId) {
		t.Error("leaf AKID does not reference the issuer SKID")
	}
	if err := verifyLeaf(t, cert.Certificate, root, "example.com"); err != nil {
		t.Fatalf("direct-signed chain did not verify against the external root: %v", err)
	}
}

func TestEnableCrossIssuerChainFileWithExtras(t *testing.T) {
	root, _, rootPEM, interPEM, interKeyPEM := makeToyHierarchy(t, false)

	m, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A chain file (issuer followed by its own issuer) is accepted; the extra
	// certificates are appended to the served chain.
	if _, err := m.EnableCrossIssuer(append(interPEM, rootPEM...), interKeyPEM); err != nil {
		t.Fatal(err)
	}
	cert, err := m.CertificateFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 4 {
		t.Fatalf("chain length = %d, want 4 (leaf, cross, issuer, root)", len(cert.Certificate))
	}
	if err := verifyLeaf(t, cert.Certificate, root, "example.com"); err != nil {
		t.Fatalf("chain did not verify: %v", err)
	}
}

func TestEnableCrossIssuerKeyMismatch(t *testing.T) {
	_, _, _, interPEM, _ := makeToyHierarchy(t, false)
	otherKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	m, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.EnableCrossIssuer(interPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err == nil {
		t.Fatal("expected key mismatch error, got nil")
	}
	if _, err := m.EnableDirectSigner(interPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err == nil {
		t.Fatal("expected key mismatch error, got nil")
	}
}

func TestEnableCrossIssuerRejectsNonCA(t *testing.T) {
	_, _, _, interPEM, interKeyPEM := makeToyHierarchy(t, false)
	m, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := m.CertificateFor("leaf.example")
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if _, err := m.EnableCrossIssuer(leafPEM, interKeyPEM); err == nil {
		t.Fatal("expected non-CA error, got nil")
	}
	if _, err := m.EnableDirectSigner(leafPEM, interKeyPEM); err == nil {
		t.Fatal("expected non-CA error, got nil")
	}
	if _, err := m.EnableCrossIssuer(interPEM, []byte("not pem")); err == nil {
		t.Fatal("expected PEM parse error, got nil")
	}
}

// openssl ecparam -genkey writes an "EC PARAMETERS" block ahead of the key;
// such files must be accepted as-is.
func TestEnableCrossIssuerOpenSSLKeyFile(t *testing.T) {
	root, _, _, interPEM, interKeyPEM := makeToyHierarchy(t, false)
	withParams := append([]byte("-----BEGIN EC PARAMETERS-----\nBgUrgQQAIg==\n-----END EC PARAMETERS-----\n"), interKeyPEM...)

	m, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.EnableCrossIssuer(interPEM, withParams); err != nil {
		t.Fatal(err)
	}
	cert, err := m.CertificateFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyLeaf(t, cert.Certificate, root, "example.com"); err != nil {
		t.Fatalf("chain did not verify: %v", err)
	}
}
