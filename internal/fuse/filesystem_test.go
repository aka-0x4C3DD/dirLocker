//go:build linux || darwin

package fuse

import (
	"context"
	"os"
	"testing"
	"time"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"bazil.org/fuse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultFS_Creation(t *testing.T) {
	logger := logging.NewTestLogger()

	// Create a mock vault (this would need to be implemented)
	mockVault := &MockVault{
		files: make(map[string]*MockFile),
	}

	fs, err := NewVaultFS(mockVault, logger, &Options{
		ReadOnly: false,
		Debug:    true,
	})

	require.NoError(t, err)
	assert.NotNil(t, fs)
	assert.Equal(t, mockVault, fs.vault)
	assert.False(t, fs.opts.ReadOnly)
	assert.True(t, fs.opts.Debug)
}

func TestVaultFS_FileOperations(t *testing.T) {
	logger := logging.NewTestLogger()

	mockVault := &MockVault{
		files: map[string]*MockFile{
			"/test.txt": {
				Name:  "/test.txt",
				Data:  []byte("Hello, World!"),
				IsDir: false,
				Size:  13,
			},
			"/subdir": {
				Name:  "/subdir",
				Data:  nil,
				IsDir: true,
				Size:  0,
			},
			"/subdir/nested.txt": {
				Name:  "/subdir/nested.txt",
				Data:  []byte("Nested file content"),
				IsDir: false,
				Size:  19,
			},
		},
	}

	fs, err := NewVaultFS(mockVault, logger, &Options{})
	require.NoError(t, err)

	// Test root directory
	root, err := fs.Root()
	require.NoError(t, err)
	assert.NotNil(t, root)

	// Test directory listing
	dir := root.(*Dir)
	entries, err := dir.ReadDirAll(context.Background())
	require.NoError(t, err)

	// Should have test.txt and subdir
	assert.Len(t, entries, 2)

	// Find test.txt entry
	var testFileEntry *fuse.Dirent
	for i := range entries {
		if entries[i].Name == "test.txt" {
			testFileEntry = &entries[i]
			break
		}
	}
	require.NotNil(t, testFileEntry)
	assert.Equal(t, "test.txt", testFileEntry.Name)
}

func TestVaultFS_FileHandles(t *testing.T) {
	logger := logging.NewTestLogger()

	mockVault := &MockVault{
		files: map[string]*MockFile{
			"/test.txt": {
				Name:  "test.txt",
				Data:  []byte("Hello, World!"),
				IsDir: false,
				Size:  13,
			},
		},
	}

	fs, err := NewVaultFS(mockVault, logger, &Options{})
	require.NoError(t, err)

	// Create file handle
	handle := fs.createFileHandle("/test.txt", []byte("Hello, World!"))

	assert.NotZero(t, handle.ID)
	assert.Equal(t, "/test.txt", handle.Path)
	assert.Equal(t, []byte("Hello, World!"), handle.Data)
	assert.False(t, handle.Modified)

	// Test reading from handle
	ctx := context.Background()
	req := &fuse.ReadRequest{
		Offset: 0,
		Size:   5,
	}
	resp := &fuse.ReadResponse{}

	err = handle.Read(ctx, req, resp)
	require.NoError(t, err)
	assert.Equal(t, []byte("Hello"), resp.Data)

	// Test writing to handle
	writeReq := &fuse.WriteRequest{
		Offset: 7,
		Data:   []byte("FUSE!"),
	}
	writeResp := &fuse.WriteResponse{}

	err = handle.Write(ctx, writeReq, writeResp)
	require.NoError(t, err)
	assert.Equal(t, 5, writeResp.Size)
	assert.True(t, handle.Modified)

	// Verify the data was written
	// Note: The write was length 5 at offset 7.
	// "Hello, World!" (len 13) -> "Hello, " (0-6) + "FUSE!" (7-11) + "!" (12)
	// So we expect "Hello, FUSE!!"
	expected := []byte("Hello, FUSE!!")
	assert.Equal(t, expected, handle.Data)
}

func TestVaultFS_ReadOnlyMode(t *testing.T) {
	logger := logging.NewTestLogger()

	mockVault := &MockVault{
		files: make(map[string]*MockFile),
	}

	fs, err := NewVaultFS(mockVault, logger, &Options{
		ReadOnly: true,
	})
	require.NoError(t, err)

	root, err := fs.Root()
	require.NoError(t, err)

	dir := root.(*Dir)

	// Test that create fails in read-only mode
	ctx := context.Background()
	req := &fuse.CreateRequest{
		Name: "newfile.txt",
		Mode: 0644,
	}
	resp := &fuse.CreateResponse{}

	_, _, err = dir.Create(ctx, req, resp)
	assert.Error(t, err)
	assert.Equal(t, fuse.EPERM, err)
}

// MockVault implements a simple mock vault for testing
type MockVault struct {
	files map[string]*MockFile
}

type MockFile struct {
	Name  string
	Data  []byte
	IsDir bool
	Size  int64
}

func (m *MockVault) GetPath() string {
	return "/tmp/test.vault"
}

func (m *MockVault) UpdateLastUsed() {
	// Mock implementation
}

func (m *MockVault) Close() error {
	return nil
}

func (m *MockVault) ListFiles() ([]vault.FileEntry, error) {
	var files []vault.FileEntry

	for _, file := range m.files {
		files = append(files, vault.FileEntry{
			Name:  file.Name,
			Size:  uint64(file.Size),
			IsDir: file.IsDir,
		})
	}

	return files, nil
}

func (m *MockVault) ExtractFile(path string) ([]byte, error) {
	if file, exists := m.files[path]; exists {
		return file.Data, nil
	}
	return nil, os.ErrNotExist
}

func (m *MockVault) AddFile(path string, data []byte) error {
	m.files[path] = &MockFile{
		Name:  path,
		Data:  data,
		IsDir: false,
		Size:  int64(len(data)),
	}
	return nil
}

func (m *MockVault) CreateDirectory(path string) error {
	m.files[path] = &MockFile{
		Name:  path,
		Data:  nil,
		IsDir: true,
		Size:  0,
	}
	return nil
}
func (m *MockVault) DeleteFile(path string) error {
	delete(m.files, path)
	return nil
}

func (m *MockVault) GetInfo() (path string, openedAt, lastUsed time.Time, isShared bool) {
	return "/mock/vault", time.Now(), time.Now(), false
}
