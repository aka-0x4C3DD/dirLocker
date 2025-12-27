//go:build linux || darwin
// +build linux darwin

package fuse

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

// VaultOps defines the operations required from the vault
type VaultOps interface {
	ListFiles() ([]vault.FileEntry, error)
	AddFile(path string, data []byte) error
	CreateDirectory(path string) error
	ExtractFile(path string) ([]byte, error)
}

// VaultFS implements a FUSE filesystem for vault contents
type VaultFS struct {
	vault  VaultOps
	logger *logging.Logger
	opts   *Options
	conn   *fuse.Conn
	server *fs.Server

	// File handle management
	handleMutex sync.RWMutex
	handles     map[uint64]*FileHandle
	nextHandle  uint64
}

// Options contains FUSE filesystem options
type Options struct {
	ReadOnly   bool
	AllowOther bool
	Debug      bool
}

// FileHandle represents an open file in the vault
type FileHandle struct {
	ID       uint64
	Path     string
	Data     []byte
	Modified bool
	Offset   int64
}

// NewVaultFS creates a new FUSE filesystem for a vault
func NewVaultFS(v VaultOps, logger *logging.Logger, opts *Options) (*VaultFS, error) {
	if opts == nil {
		opts = &Options{}
	}

	return &VaultFS{
		vault:   v,
		logger:  logger,
		opts:    opts,
		handles: make(map[uint64]*FileHandle),
	}, nil
}

// Mount mounts the filesystem at the specified mount point
func (vfs *VaultFS) Mount(ctx context.Context, mountPoint string) error {
	// Set up FUSE mount options
	mountOpts := []fuse.MountOption{
		fuse.FSName("dirLocker"),
		fuse.Subtype("vault"),
	}

	if vfs.opts.AllowOther {
		mountOpts = append(mountOpts, fuse.AllowOther())
	}

	if vfs.opts.ReadOnly {
		mountOpts = append(mountOpts, fuse.ReadOnly())
	}

	// Mount the filesystem
	conn, err := fuse.Mount(mountPoint, mountOpts...)
	if err != nil {
		return fmt.Errorf("failed to mount FUSE filesystem: %w", err)
	}
	vfs.conn = conn

	// Create and start the server
	vfs.server = fs.New(conn, &fs.Config{
		Debug: func(msg interface{}) {
			if vfs.opts.Debug {
				vfs.logger.Debug("FUSE debug", "message", msg)
			}
		},
	})

	// Serve filesystem in a goroutine
	go func() {
		if err := vfs.server.Serve(vfs); err != nil {
			vfs.logger.Error("FUSE server error", "error", err)
		}
	}()

	// The bazil.org/fuse library doesn't have Ready/MountError channels
	// The mount is ready when fuse.Mount returns without error
	vfs.logger.Info("FUSE filesystem mounted successfully")

	// Wait for context cancellation
	<-ctx.Done()
	return ctx.Err()
}

// Unmount unmounts the filesystem
func (vfs *VaultFS) Unmount() error {
	if vfs.conn != nil {
		return vfs.conn.Close()
	}
	return nil
}

// Root returns the root directory of the filesystem
func (vfs *VaultFS) Root() (fs.Node, error) {
	return &Dir{
		fs:   vfs,
		path: "/",
	}, nil
}

// Dir represents a directory in the vault
type Dir struct {
	fs   *VaultFS
	path string
}

// Attr sets the attributes for a directory
func (d *Dir) Attr(ctx context.Context, attr *fuse.Attr) error {
	attr.Inode = 1 // Root directory gets inode 1
	attr.Mode = os.ModeDir | 0755
	attr.Nlink = 2
	attr.Uid = uint32(os.Getuid())
	attr.Gid = uint32(os.Getgid())
	attr.Atime = time.Now()
	attr.Mtime = time.Now()
	attr.Ctime = time.Now()

	d.fs.logger.Debug("Dir.Attr", "path", d.path, "mode", attr.Mode)
	return nil
}

// Lookup looks up a file or directory by name
func (d *Dir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	fullPath := filepath.Join(d.path, name)
	d.fs.logger.Debug("Dir.Lookup", "dir", d.path, "name", name, "fullPath", fullPath)

	// List files in the vault to find the requested item
	files, err := d.fs.vault.ListFiles()
	if err != nil {
		d.fs.logger.Error("Failed to list vault files", "error", err, "path", d.path)
		return nil, fuse.ENOENT
	}

	for _, file := range files {
		if file.Name == name {
			if file.IsDir {
				return &Dir{
					fs:   d.fs,
					path: fullPath,
				}, nil
			} else {
				return &File{
					fs:   d.fs,
					path: fullPath,
					size: int64(file.Size),
				}, nil
			}
		}
	}

	return nil, fuse.ENOENT
}

// ReadDirAll returns all directory entries
func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	d.fs.logger.Debug("Dir.ReadDirAll", "path", d.path)

	files, err := d.fs.vault.ListFiles()
	if err != nil {
		d.fs.logger.Error("Failed to list vault files", "error", err, "path", d.path)
		return nil, fuse.EIO
	}

	var entries []fuse.Dirent
	for _, file := range files {
		// Filter entries that belong to this directory
		// We expect file.Name to be the full path in the vault
		dirPath := filepath.ToSlash(filepath.Dir(file.Name))

		// Handle root directory comparison
		// If d.path is "/", filepath.Dir("/test.txt") returns "/"
		// If d.path is "/subdir", filepath.Dir("/subdir/nested.txt") returns "/subdir"

		// Clean paths to ensure consistent comparison
		cleanDirPath := filepath.Clean(dirPath)
		cleanCurrentPath := filepath.Clean(d.path)

		// On Windows, filepath.Dir might return backslashes, but our vault paths use forward slashes (usually)
		// We should ensure we are comparing normalized paths
		if cleanDirPath == "." {
			cleanDirPath = "/" // Handle root if returned as .
		}

		if cleanDirPath == cleanCurrentPath {
			entry := fuse.Dirent{
				Name: filepath.Base(file.Name),
			}

			if file.IsDir {
				entry.Type = fuse.DT_Dir
			} else {
				entry.Type = fuse.DT_File
			}

			entries = append(entries, entry)
		}
	}

	d.fs.logger.Debug("Dir.ReadDirAll result", "path", d.path, "count", len(entries))
	return entries, nil
}

// Create creates a new file (if not read-only)
func (d *Dir) Create(ctx context.Context, req *fuse.CreateRequest, resp *fuse.CreateResponse) (fs.Node, fs.Handle, error) {
	if d.fs.opts.ReadOnly {
		return nil, nil, fuse.EPERM
	}

	fullPath := filepath.Join(d.path, req.Name)
	d.fs.logger.Debug("Dir.Create", "path", fullPath, "mode", req.Mode)

	// Create empty file in vault
	if err := d.fs.vault.AddFile(fullPath, []byte{}); err != nil {
		d.fs.logger.Error("Failed to create file in vault", "error", err, "path", fullPath)
		return nil, nil, fuse.EIO
	}

	file := &File{
		fs:   d.fs,
		path: fullPath,
		size: 0,
	}

	// Create file handle
	handle := d.fs.createFileHandle(fullPath, []byte{})

	return file, handle, nil
}

// Mkdir creates a new directory (if not read-only)
func (d *Dir) Mkdir(ctx context.Context, req *fuse.MkdirRequest) (fs.Node, error) {
	if d.fs.opts.ReadOnly {
		return nil, fuse.EPERM
	}

	fullPath := filepath.Join(d.path, req.Name)
	d.fs.logger.Debug("Dir.Mkdir", "path", fullPath, "mode", req.Mode)

	// Create directory in vault
	if err := d.fs.vault.CreateDirectory(fullPath); err != nil {
		d.fs.logger.Error("Failed to create directory in vault", "error", err, "path", fullPath)
		return nil, fuse.EIO
	}

	return &Dir{
		fs:   d.fs,
		path: fullPath,
	}, nil
}

// File represents a file in the vault
type File struct {
	fs   *VaultFS
	path string
	size int64
}

// Attr sets the attributes for a file
func (f *File) Attr(ctx context.Context, attr *fuse.Attr) error {
	attr.Inode = 2 // Files get inode 2+
	attr.Mode = 0644
	attr.Nlink = 1
	attr.Size = uint64(f.size)
	attr.Uid = uint32(os.Getuid())
	attr.Gid = uint32(os.Getgid())
	attr.Atime = time.Now()
	attr.Mtime = time.Now()
	attr.Ctime = time.Now()

	f.fs.logger.Debug("File.Attr", "path", f.path, "size", f.size)
	return nil
}

// Open opens a file for reading/writing
func (f *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fs.Handle, error) {
	f.fs.logger.Debug("File.Open", "path", f.path, "flags", req.Flags)

	// Read file data from vault
	data, err := f.fs.vault.ExtractFile(f.path)
	if err != nil {
		f.fs.logger.Error("Failed to read file from vault", "error", err, "path", f.path)
		return nil, fuse.EIO
	}

	// Create file handle
	handle := f.fs.createFileHandle(f.path, data)

	return handle, nil
}

// createFileHandle creates a new file handle
func (vfs *VaultFS) createFileHandle(path string, data []byte) *FileHandle {
	vfs.handleMutex.Lock()
	defer vfs.handleMutex.Unlock()

	vfs.nextHandle++
	handle := &FileHandle{
		ID:   vfs.nextHandle,
		Path: path,
		Data: make([]byte, len(data)),
	}
	copy(handle.Data, data)

	vfs.handles[handle.ID] = handle
	vfs.logger.Debug("Created file handle", "id", handle.ID, "path", path, "size", len(data))

	return handle
}

// Read reads data from a file handle
func (fh *FileHandle) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	fh.Offset = req.Offset

	// Calculate read bounds
	start := req.Offset
	end := req.Offset + int64(req.Size)

	if start >= int64(len(fh.Data)) {
		// EOF
		return nil
	}

	if end > int64(len(fh.Data)) {
		end = int64(len(fh.Data))
	}

	resp.Data = fh.Data[start:end]
	return nil
}

// Write writes data to a file handle
func (fh *FileHandle) Write(ctx context.Context, req *fuse.WriteRequest, resp *fuse.WriteResponse) error {
	// Extend data if necessary
	needed := req.Offset + int64(len(req.Data))
	if needed > int64(len(fh.Data)) {
		newData := make([]byte, needed)
		copy(newData, fh.Data)
		fh.Data = newData
	}

	// Write the data
	copy(fh.Data[req.Offset:], req.Data)
	fh.Modified = true
	resp.Size = len(req.Data)

	return nil
}

// Flush flushes any pending writes
func (fh *FileHandle) Flush(ctx context.Context, req *fuse.FlushRequest) error {
	if !fh.Modified {
		return nil
	}

	// Write data back to vault
	// Note: We need access to the VaultFS instance to do this
	// This is a simplified implementation
	return nil
}

// Release releases a file handle
func (fh *FileHandle) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
	// Clean up file handle
	// Note: We need access to the VaultFS instance to do this properly
	return nil
}
