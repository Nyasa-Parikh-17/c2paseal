package middleware_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/middleware"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
)

func ExampleSign() {
	// The TEST ONLY certificate; use sign.OpenKey for a key in a KMS.
	chain, key, err := c2paseal.LoadSigner("../testdata/pki/leaf-chain.pem", "../testdata/pki/leaf.key")
	if err != nil {
		log.Fatal(err)
	}
	mw, err := middleware.Sign(middleware.Config{
		Options:           &sign.Options{Chain: chain, Signer: key},
		RejectUnsupported: true,
		Prepare: func(r *http.Request, f *middleware.File, o *sign.Options) error {
			o.Title = f.Filename
			return nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// The upload handler gets the signed file.
	upload := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file, hdr, err := r.FormFile("photo")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()
		b, _ := io.ReadAll(file)
		ms, err := c2paseal.ReadBytes(b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%s: signed, title %q", hdr.Filename, ms.Active.Claim.Title)
	})
	srv := httptest.NewServer(mw(upload))
	defer srv.Close()

	// A client uploads a photo.
	photo, err := os.ReadFile("../testdata/unsigned/small.jpg")
	if err != nil {
		log.Fatal(err)
	}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	fw, _ := w.CreateFormFile("photo", "holiday.jpg")
	fw.Write(photo)
	w.Close()
	resp, err := http.Post(srv.URL, w.FormDataContentType(), &body)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(resp.Body)
	fmt.Println(string(answer))
	// Output: holiday.jpg: signed, title "holiday.jpg"
}
