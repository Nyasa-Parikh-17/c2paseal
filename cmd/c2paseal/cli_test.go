package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every command answers -h with its usage and exit 0.
func TestHelp(t *testing.T) {
	for _, cmd := range []string{"inspect", "verify", "sign", "serve", "version"} {
		var stderr bytes.Buffer
		if code := run([]string{cmd, "-h"}, io.Discard, &stderr); code != exitValid || !strings.Contains(stderr.String(), "usage: c2paseal "+cmd) {
			t.Errorf("%s -h: exit %d, output %q", cmd, code, stderr.String())
		}
	}
	var stdout bytes.Buffer
	if code := run([]string{"help"}, &stdout, io.Discard); code != exitValid || !strings.Contains(stdout.String(), "exit codes:") {
		t.Errorf("help: exit %d", code)
	}
}

// With --json, every command prints JSON on stdout, errors included.
func TestJSONEverywhere(t *testing.T) {
	cert, key := fixture(t, "pki/leaf-chain.pem"), fixture(t, "pki/leaf.key")
	out := filepath.Join(t.TempDir(), "out.png")
	tests := []struct {
		args []string
		code int
		key  string // a key the JSON object must have
	}{
		{[]string{"inspect", "--json", fixture(t, "signed/small.png")}, exitValid, "active_manifest"},
		{[]string{"inspect", "--json", fixture(t, "unsigned/small.png")}, exitInvalid, "error"},
		{[]string{"inspect", fixture(t, "unsigned/small.png")}, exitInvalid, "error"},
		{[]string{"verify", "--json", fixture(t, "broken/data-flip.png")}, exitInvalid, "validation_state"},
		{[]string{"verify", "--json", "--trust", "nope.pem", fixture(t, "signed/small.png")}, exitUsage, "error"},
		{[]string{"sign", "--json", "--cert", cert, "--key", key, "--in", fixture(t, "unsigned/small.png"), "--out", out}, exitValid, "active_manifest"},
		{[]string{"sign", "--json", "--cert", cert, "--key", key, "--in", cert, "--out", out}, exitInvalid, "error"},
		{[]string{"sign", "--json", "--cert", cert, "--key", cert, "--in", out, "--out", out}, exitUsage, "error"},
		{[]string{"version", "--json"}, exitValid, "version"},
	}
	for _, tt := range tests {
		var stdout bytes.Buffer
		code := run(tt.args, &stdout, io.Discard)
		var v map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &v); err != nil || code != tt.code || v[tt.key] == nil {
			t.Errorf("run(%q): exit %d (want %d), JSON %v, key %q in %s", tt.args, code, tt.code, err, tt.key, stdout.String())
		}
	}
}

func TestServe(t *testing.T) {
	if code := run([]string{"serve", "--pki", t.TempDir()}, io.Discard, io.Discard); code != exitUsage {
		t.Errorf("serve with an empty PKI dir: exit %d, want %d", code, exitUsage)
	}
	if code := run([]string{"serve", "extra"}, io.Discard, io.Discard); code != exitUsage {
		t.Errorf("serve extra: exit %d", code)
	}

	// Start on a free port, fetch the page, then cancel.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int)
	var stdout bytes.Buffer
	go func() {
		done <- serveCmd(ctx, []string{"--addr", addr, "--pki", fixture(t, "pki")}, &stdout, io.Discard)
	}()
	var resp *http.Response
	for i := 0; i < 50; i++ {
		if resp, err = http.Get("http://" + addr + "/"); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(page, []byte("TEST ONLY")) {
		t.Error("page lacks the TEST ONLY label")
	}
	cancel()
	select {
	case code := <-done:
		if code != exitValid || !strings.Contains(stdout.String(), "TEST ONLY") {
			t.Errorf("serve: exit %d, output %q", code, stdout.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
}
