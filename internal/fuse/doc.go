// Package fuse implements the FUSE filesystem interface for dirLocker.
//
// This package provides a virtual filesystem view of the encrypted vault,
// allowing users to mount and interact with their locked directories
// transparently.
//
// Note: The FUSE implementation is currently only available on Linux and macOS.
// On Windows, this package provides a stub or empty implementation to allow
// compilation, but the mounting functionality will be disabled or unavailable.
package fuse
