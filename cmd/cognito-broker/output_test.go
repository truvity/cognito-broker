package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The file holds a live bearer token. 0644 would leave it readable by
// every account on a shared machine for the whole of its lifetime.
func TestOpenOutputCreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")

	w, closeOut, err := openOutput(path)
	if err != nil {
		t.Fatalf("openOutput: %v", err)
	}

	if _, err := w.Write([]byte("secret")); err != nil {
		t.Fatal(err)
	}

	closeOut()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

// O_CREATE applies the mode only when the file did not already exist, so
// an existing world-readable file would otherwise keep its permissions
// and quietly receive a token.
func TestOpenOutputTightensAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale.json")

	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, closeOut, err := openOutput(path)
	if err != nil {
		t.Fatalf("openOutput: %v", err)
	}

	closeOut()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600 — an existing loose file kept its permissions", perm)
	}
}

func TestOpenOutputDashIsStdout(t *testing.T) {
	w, closeOut, err := openOutput("-")
	if err != nil {
		t.Fatal(err)
	}

	defer closeOut()

	if w != os.Stdout {
		t.Error("- should select stdout")
	}
}
