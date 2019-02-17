package ftp

import "testing"

func TestValidStatusText(t *testing.T) {
	txt := StatusText(StatusInvalidCredentials)
	if txt == "" {
		t.Fatal("exptected status text, got empty string")
	}
}

func TestInvalidStatusText(t *testing.T) {
	txt := StatusText(0)
	if txt != "" {
		t.Fatalf("got status text %q, expected empty string", txt)
	}
}
