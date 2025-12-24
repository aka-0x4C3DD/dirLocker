package tests

import (
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"testing/quick"
	"time"

	"dirLocker/pkg/vault"
)

func TestVaultProperties(t *testing.T) {
	rand.Seed(time.Now().UnixNano()) // Ensure randomness
	t.Run("ReadAfterWrite", testPropertyReadAfterWrite)
	t.Run("CountIncrements", testPropertyCountIncrements)
}

func testPropertyReadAfterWrite(t *testing.T) {
	f := func(name string, data []byte) bool {
		if len(name) == 0 {
			return true
		}
		cleanName := filterString(name)
		if cleanName == "" {
			return true
		}
		if len(cleanName) > 100 {
			cleanName = cleanName[:100]
		}

		tmpDir, err := os.MkdirTemp("", "prop_rw")
		if err != nil {
			return false
		}
		defer os.RemoveAll(tmpDir)

		vPath := filepath.Join(tmpDir, "prop.vault")
		v, err := vault.CreateVault(vPath, "password", vault.CipherXChaCha20Poly1305)
		if err != nil {
			return false
		}
		defer v.Close()

		if err := v.AddFile(cleanName, data); err != nil {
			return false
		}

		extracted, err := v.ExtractFile(cleanName)
		if err != nil {
			return false
		}

		return string(extracted) == string(data)
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 20}); err != nil {
		t.Error(err)
	}
}

func testPropertyCountIncrements(t *testing.T) {
	f := func(name string) bool {
		cleanName := filterString(name)
		if cleanName == "" {
			return true
		}
		if len(cleanName) > 50 {
			cleanName = cleanName[:50]
		}

		tmpDir, err := os.MkdirTemp("", "prop_count")
		if err != nil {
			return false
		}
		defer os.RemoveAll(tmpDir)

		vPath := filepath.Join(tmpDir, "count.vault")
		v, err := vault.CreateVault(vPath, "password", vault.CipherXChaCha20Poly1305)
		if err != nil {
			return false
		}
		defer v.Close()

		entries, err := v.ListFiles()
		if err != nil {
			return false
		}
		initialCount := len(entries)

		if err := v.AddFile(cleanName, []byte("data")); err != nil {
			return false
		}

		entriesAfter, err := v.ListFiles()
		if err != nil {
			return false
		}

		return len(entriesAfter) == initialCount+1
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 20}); err != nil {
		t.Error(err)
	}
}

func filterString(s string) string {
	out := ""
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			out += string(r)
		}
	}
	return out
}
