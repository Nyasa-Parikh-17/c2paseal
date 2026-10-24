package c2paseal

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
)

// SignOptions configures Sign. Chain and Signer are required; see
// sign.Options for the rest.
type SignOptions = sign.Options

// ErrSignFormat is returned when asked to sign a file format the signer
// does not support yet (only JPEG).
var ErrSignFormat = errors.New("c2paseal: signing supports JPEG only")

// Sign reads the JPEG at in, embeds a newly signed C2PA manifest store and
// writes the result to out (atomically, via a temporary file in out's
// directory). An existing manifest store in the input is replaced.
func Sign(in, out string, opts *SignOptions) error {
	b, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("c2paseal: %w", err)
	}
	signed, err := SignBytes(b, opts)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(out), ".c2paseal-*")
	if err != nil {
		return fmt.Errorf("c2paseal: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(signed); err != nil {
		tmp.Close()
		return fmt.Errorf("c2paseal: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("c2paseal: %w", err)
	}
	if err := os.Rename(tmp.Name(), out); err != nil {
		return fmt.Errorf("c2paseal: %w", err)
	}
	return nil
}

// SignBytes is Sign for a file already in memory.
func SignBytes(b []byte, opts *SignOptions) ([]byte, error) {
	if asset.Detect(b) != asset.JPEG {
		return nil, ErrSignFormat
	}
	return sign.JPEG(b, opts)
}

// LoadSigner reads a PEM certificate chain (signer first, then
// intermediates) and a PEM private key (PKCS #8 or SEC 1 EC).
func LoadSigner(certPath, keyPath string) ([]*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("c2paseal: certificate: %w", err)
	}
	var chain []*x509.Certificate
	for blk, rest := pem.Decode(certPEM); blk != nil; blk, rest = pem.Decode(rest) {
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("c2paseal: certificate: %w", err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, nil, errors.New("c2paseal: certificate: no PEM certificates in " + certPath)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("c2paseal: key: %w", err)
	}
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, nil, errors.New("c2paseal: key: no PEM block in " + keyPath)
	}
	var key any
	switch blk.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(blk.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("c2paseal: key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("c2paseal: key: %T cannot sign", key)
	}
	return chain, signer, nil
}
