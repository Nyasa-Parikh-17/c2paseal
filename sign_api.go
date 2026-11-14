package c2paseal

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal/sign"
)

// SignOptions configures Sign. Chain and Signer are required; see
// sign.Options for the rest.
type SignOptions = sign.Options

// ErrSignFormat is returned when asked to sign a file that is neither JPEG
// nor PNG.
var ErrSignFormat = sign.ErrFormat

// SignedAsset is the result of SignAsset: the signed file and its manifest
// store.
type SignedAsset = sign.Signed

// Sign reads the JPEG or PNG at in, signs it and writes the result to out
// (atomically, via a temporary file in out's directory).
//
// If in already has a manifest store, it is kept and recorded as the
// parent ingredient of the new manifest (SignOptions.NoHistory replaces it
// instead). With SignOptions.Sidecar the store is not embedded but written
// next to out, at SidecarPath(out).
func Sign(in, out string, opts *SignOptions) error {
	b, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("c2paseal: %w", err)
	}
	s, err := SignAsset(b, opts)
	if err != nil {
		return err
	}
	if err := writeAtomic(out, s.File); err != nil {
		return err
	}
	if opts.Sidecar {
		return writeAtomic(SidecarPath(out), s.Store)
	}
	return nil
}

// SignBytes is Sign for a file already in memory. It returns only the
// signed file, so it rejects SignOptions.Sidecar; use SignAsset for that.
func SignBytes(b []byte, opts *SignOptions) ([]byte, error) {
	if opts != nil && opts.Sidecar {
		return nil, sign.ErrSidecar
	}
	s, err := SignAsset(b, opts)
	if err != nil {
		return nil, err
	}
	return s.File, nil
}

// SignAsset signs a JPEG or PNG held in memory and returns the signed file
// and its manifest store (embedded in the file, or, with
// SignOptions.Sidecar, to be saved as a sidecar or served at
// SignOptions.RemoteURL).
func SignAsset(b []byte, opts *SignOptions) (*SignedAsset, error) {
	return sign.Asset(b, opts)
}

// SidecarPath returns where a file's sidecar manifest store goes: the same
// path with the extension .c2pa (C2PA 2.4 §15.5.3.1).
func SidecarPath(path string) string {
	return strings.TrimSuffix(path, filepath.Ext(path)) + ".c2pa"
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".c2paseal-*")
	if err != nil {
		return fmt.Errorf("c2paseal: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("c2paseal: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("c2paseal: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("c2paseal: %w", err)
	}
	return nil
}

// LoadSigner reads a PEM certificate chain (signer first, then
// intermediates) and a PEM private key (PKCS #8 or SEC 1 EC).
func LoadSigner(certPath, keyPath string) ([]*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("c2paseal: certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("c2paseal: key: %w", err)
	}
	return parseSigner(certPEM, keyPEM, certPath, keyPath)
}

// ParseSigner is LoadSigner on the PEM bytes, for callers without files
// (such as the WebAssembly build).
func ParseSigner(certPEM, keyPEM []byte) ([]*x509.Certificate, crypto.Signer, error) {
	return parseSigner(certPEM, keyPEM, "the certificate input", "the key input")
}

// parseSigner parses a chain and a key; certName and keyName are used in
// errors.
func parseSigner(certPEM, keyPEM []byte, certName, keyName string) ([]*x509.Certificate, crypto.Signer, error) {
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
		return nil, nil, errors.New("c2paseal: certificate: no PEM certificates in " + certName)
	}

	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, nil, errors.New("c2paseal: key: no PEM block in " + keyName)
	}
	var key any
	var err error
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
