// Command upload-server is a photo upload service that signs every upload
// with C2PA Content Credentials, using the C2paSeal HTTP middleware.
//
//	go run ./upload-server --cert chain.pem --key key.pem --dir uploads
//	curl -F photo=@holiday.jpg http://127.0.0.1:8080/upload
//
// --key is a PEM file or a key URI. For a key in AWS KMS or Google Cloud
// KMS, add one import to this file and pass the key's URI:
//
//	import _ "github.com/Nyasa-Parikh-17/c2paseal/keys/awskms"
//	go run ./upload-server --cert chain.pem --key "awskms:arn:aws:kms:…"
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/middleware"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
)

func main() {
	fs := flag.NewFlagSet("upload-server", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	cert := fs.String("cert", "", "PEM certificate chain, signer first")
	key := fs.String("key", "", "the signing key: a PEM file or a key URI")
	dir := fs.String("dir", "uploads", "where signed uploads are saved")
	fs.Parse(os.Args[1:])
	h, err := newServer(context.Background(), *cert, *key, *dir)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on http://%s (POST /upload, field \"photo\")", *addr)
	log.Fatal(http.ListenAndServe(*addr, h))
}

// newServer builds the handler: the middleware signs, upload saves.
func newServer(ctx context.Context, certPath, keyURI, dir string) (http.Handler, error) {
	if certPath == "" || keyURI == "" {
		return nil, errors.New("--cert and --key are required")
	}
	chain, err := c2paseal.LoadChain(certPath)
	if err != nil {
		return nil, err
	}
	signer, err := sign.OpenKey(ctx, keyURI) // file:, plain paths, or a registered KMS scheme
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	signUploads, err := middleware.Sign(middleware.Config{
		Options:           &sign.Options{Chain: chain, Signer: signer},
		Fields:            []string{"photo"},
		RejectUnsupported: true,
		MaxBytes:          20 << 20,
		Prepare: func(r *http.Request, f *middleware.File, o *sign.Options) error {
			o.Title = f.Filename
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("POST /upload", signUploads(upload(dir)))
	return mux, nil
}

var safeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// upload saves the (already signed) photo and answers with what was done.
func upload(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file, hdr, err := r.FormFile("photo")
		if err != nil {
			http.Error(w, `form field "photo" missing`, http.StatusBadRequest)
			return
		}
		defer file.Close()
		name := safeName.ReplaceAllString(filepath.Base(hdr.Filename), "_")
		dst, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			http.Error(w, "cannot save", http.StatusInternalServerError)
			return
		}
		_, err = io.Copy(dst, file)
		if cerr := dst.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			http.Error(w, "cannot save", http.StatusInternalServerError)
			return
		}
		var signed middleware.File
		for _, f := range middleware.Files(r) {
			if f.Field == "photo" {
				signed = f
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"saved":  name,
			"format": signed.Format,
			"signed": signed.Signed,
			"parent": signed.Parent, // it already had Content Credentials
			"bytes":  signed.Size,
		})
	})
}
