package main

import (
	"io"
	"testing"
)

func TestRunUsage(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"unknown command", []string{"frobnicate"}},
		{"bad flag", []string{"-nope"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(tt.args, io.Discard, io.Discard); got != exitUsage {
				t.Errorf("run(%q) = %d, want %d", tt.args, got, exitUsage)
			}
		})
	}
}
