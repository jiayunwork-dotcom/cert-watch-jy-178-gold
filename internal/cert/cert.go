// Package cert loads X.509 certificates from local files (PEM or DER) and
// summarizes their expiry status. It performs no network calls: it only reads
// certificates that already exist on disk, which makes it safe to run offline
// in a pre-renewal monitoring pipeline.
package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// Status classifies a certificate relative to its expiry.
type Status string

const (
	StatusOK      Status = "OK"
	StatusWarn    Status = "WARN" // expiring within the warn window
	StatusExpired Status = "EXPIRED"
)

// CertInfo is the parsed summary of a single certificate.
type CertInfo struct {
	Path      string
	Subject   string
	NotBefore time.Time
	NotAfter  time.Time
	DaysLeft  int
	Status    Status
}

// LoadCert reads one certificate file and computes its status. warnDays
// controls the threshold at or below which a still-valid cert is flagged WARN.
func LoadCert(path string, warnDays int) (CertInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CertInfo{}, err
	}

	// Collect every CERTIFICATE block (handles concatenated/bundle files).
	var blocks []*pem.Block
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			blocks = append(blocks, b)
		}
	}

	var der []byte
	if len(blocks) > 0 {
		der = blocks[0].Bytes // leaf / first cert
	} else {
		// Fall back to treating the whole file as DER.
		if _, err := x509.ParseCertificate(data); err != nil {
			return CertInfo{}, fmt.Errorf("no CERTIFICATE found in %q", path)
		}
		der = data
	}

	c, err := x509.ParseCertificate(der)
	if err != nil {
		return CertInfo{}, fmt.Errorf("parse %q: %w", path, err)
	}

	info := CertInfo{
		Path:      path,
		Subject:   c.Subject.CommonName,
		NotBefore: c.NotBefore,
		NotAfter:  c.NotAfter,
	}
	if info.Subject == "" && len(c.DNSNames) > 0 {
		info.Subject = c.DNSNames[0]
	}
	if info.Subject == "" {
		info.Subject = c.Subject.String()
	}

	now := time.Now()
	info.DaysLeft = int(c.NotAfter.Sub(now).Hours() / 24)
	switch {
	case c.NotAfter.Before(now):
		info.Status = StatusExpired
	case info.DaysLeft <= warnDays:
		info.Status = StatusWarn
	default:
		info.Status = StatusOK
	}
	return info, nil
}

// LoadAll loads every certificate in paths (order preserved).
func LoadAll(paths []string, warnDays int) ([]CertInfo, error) {
	out := make([]CertInfo, 0, len(paths))
	for _, p := range paths {
		ci, err := LoadCert(p, warnDays)
		if err != nil {
			return nil, err
		}
		out = append(out, ci)
	}
	return out, nil
}
