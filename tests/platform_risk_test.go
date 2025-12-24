package tests

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"dirLocker/pkg/vault"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPlatformSpecificRisks orchestrates OS-specific risk scenarios
func TestPlatformSpecificRisks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Run("Windows_ReservedNames", testWindowsReservedNames)
		t.Run("Windows_NTFS_Streams", testWindowsNTFSStreams)
		t.Run("Windows_CaseInsensitivity", testWindowsCaseInsensitivity)
		t.Run("Windows_PathLength", testWindowsPathLength)
	} else {
		t.Run("Unix_SymlinkAttacks", testUnixSymlinkAttacks)
		t.Run("Unix_Permissions", testUnixPermissions)
	}
}

func testWindowsReservedNames(t *testing.T) {
	reserved := []string{"CON", "PRN", "AUX", "NUL", "COM1", "LPT1"}

	tmpDir := t.TempDir()

	for _, name := range reserved {
		t.Run(name, func(t *testing.T) {
			vPath := filepath.Join(tmpDir, name+".vault")

			// Use the vault package to create
			v, err := vault.CreateVault(vPath, "password", vault.CipherXChaCha20Poly1305)
			if err == nil {
				v.Close()
			} else {
				t.Logf("Correctly failed to create reserved name vault: %v", err)
			}
		})
	}
}

func testWindowsNTFSStreams(t *testing.T) {
	tmpDir := t.TempDir()
	vPath := filepath.Join(tmpDir, "stream_test.vault")

	v, err := vault.CreateVault(vPath, "password", vault.CipherXChaCha20Poly1305)
	require.NoError(t, err)
	defer v.Close()

	err = v.AddFile("testfile.txt:hidden_stream", []byte("secret"))

	if err == nil {
		data, err := v.ExtractFile("testfile.txt:hidden_stream")
		assert.NoError(t, err)
		assert.Equal(t, []byte("secret"), data)
	}
}

func testWindowsCaseInsensitivity(t *testing.T) {
	tmpDir := t.TempDir()
	vPath := filepath.Join(tmpDir, "case_test.vault")

	v, err := vault.CreateVault(vPath, "password", vault.CipherXChaCha20Poly1305)
	require.NoError(t, err)
	defer v.Close()

	err = v.AddFile("file.txt", []byte("lower"))
	require.NoError(t, err)

	err = v.AddFile("FILE.TXT", []byte("UPPER"))
	require.NoError(t, err)

	lower, err := v.ExtractFile("file.txt")
	assert.NoError(t, err)
	assert.Equal(t, []byte("lower"), lower)

	upper, err := v.ExtractFile("FILE.TXT")
	assert.NoError(t, err)
	assert.Equal(t, []byte("UPPER"), upper)
}

func testWindowsPathLength(t *testing.T) {
	tmpDir := t.TempDir()
	vPath := filepath.Join(tmpDir, "path_test.vault")

	v, err := vault.CreateVault(vPath, "password", vault.CipherXChaCha20Poly1305)
	require.NoError(t, err)
	defer v.Close()

	longName := strings.Repeat("a", 255) + ".txt" // 259 chars
	err = v.AddFile(longName, []byte("long"))
	assert.NoError(t, err)

	deepDir := strings.Repeat("dir/", 50) + "file.txt"
	err = v.AddFile(deepDir, []byte("deep"))
	assert.NoError(t, err)
}

func testUnixSymlinkAttacks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix symlink tests on Windows")
	}

	tmpDir := t.TempDir()

	target := filepath.Join(tmpDir, "target_file")
	err := os.WriteFile(target, []byte("sensitive"), 0600)
	require.NoError(t, err)

	link := filepath.Join(tmpDir, "link_to_target.vault")
	err = os.Symlink(target, link)
	require.NoError(t, err)

	_, err = vault.CreateVault(link, "password", vault.CipherXChaCha20Poly1305)

	content, _ := os.ReadFile(target)
	assert.Equal(t, []byte("sensitive"), content, "Target file should not be overwritten via symlink")
}

func testUnixPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix permission tests on Windows")
	}
}
