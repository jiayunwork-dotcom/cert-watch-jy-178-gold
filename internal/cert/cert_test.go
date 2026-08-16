package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCert(t *testing.T, dir, name string, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCertValid(t *testing.T) {
	dir := t.TempDir()
	path := writeCert(t, dir, "ok.pem", time.Now().Add(90*24*time.Hour))
	ci, err := LoadCert(path, 30)
	if err != nil {
		t.Fatal(err)
	}
	if ci.Status != StatusOK {
		t.Fatalf("expected OK, got %s", ci.Status)
	}
	if ci.DaysLeft <= 30 {
		t.Fatalf("expected daysLeft > 30, got %d", ci.DaysLeft)
	}
	if ci.Subject != "example.com" {
		t.Fatalf("subject = %q", ci.Subject)
	}
}

func TestLoadCertExpired(t *testing.T) {
	dir := t.TempDir()
	path := writeCert(t, dir, "old.pem", time.Now().Add(-48*time.Hour))
	ci, err := LoadCert(path, 30)
	if err != nil {
		t.Fatal(err)
	}
	if ci.Status != StatusExpired {
		t.Fatalf("expected EXPIRED, got %s", ci.Status)
	}
	if ci.DaysLeft >= 0 {
		t.Fatalf("expected negative days left, got %d", ci.DaysLeft)
	}
}

func TestLoadCertWarn(t *testing.T) {
	dir := t.TempDir()
	path := writeCert(t, dir, "soon.pem", time.Now().Add(10*24*time.Hour))
	ci, err := LoadCert(path, 30)
	if err != nil {
		t.Fatal(err)
	}
	if ci.Status != StatusWarn {
		t.Fatalf("expected WARN, got %s", ci.Status)
	}
}

func TestLoadCert_InvalidFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(path, []byte("this is not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCert(path, 30)
	if err == nil {
		t.Fatal("expected error for non-certificate file")
	}
}

func TestLoadCert_WarnIncludesExactDays(t *testing.T) {
	dir := t.TempDir()
	path := writeCert(t, dir, "edge.pem", time.Now().Add(30*24*time.Hour+2*time.Hour))
	ci, err := LoadCert(path, 30)
	if err != nil {
		t.Fatal(err)
	}
	if ci.DaysLeft != 30 {
		t.Fatalf("expected DaysLeft=30, got %d", ci.DaysLeft)
	}
	if ci.Status != StatusWarn {
		t.Fatalf("expected WARN at exact warnDays, got %s", ci.Status)
	}
}

func TestLoadCert_SubjectFallsBackToDNS(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{"dns-only.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "dns.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	ci, err := LoadCert(path, 30)
	if err != nil {
		t.Fatal(err)
	}
	if ci.Subject != "dns-only.example" {
		t.Fatalf("subject = %q, want dns-only.example", ci.Subject)
	}
}

func TestLoadAll_StopsOnFirstError(t *testing.T) {
	dir := t.TempDir()
	ok := writeCert(t, dir, "ok.pem", time.Now().Add(90*24*time.Hour))
	missing := filepath.Join(dir, "missing.pem")
	_, err := LoadAll([]string{ok, missing}, 30)
	if err == nil {
		t.Fatal("expected error when a path is missing")
	}
}
