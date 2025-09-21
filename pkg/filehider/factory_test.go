package filehider

import (
	"testing"
)

func TestNewFileHider(t *testing.T) {
	hider, err := NewFileHider()
	if err != nil {
		t.Fatalf("Failed to create file hider: %v", err)
	}

	if hider == nil {
		t.Error("File hider should not be nil")
	}

	// Verify the correct implementation is returned based on platform
	// We can't directly check the type due to build constraints,
	// but we can verify that we got a valid FileHider implementation
	if hider == nil {
		t.Error("FileHider should not be nil")
	}

	// Test that the interface methods are available
	hiddenFiles, err := hider.ListHidden()
	if err != nil {
		t.Errorf("ListHidden should work: %v", err)
	}

	if hiddenFiles == nil {
		t.Error("ListHidden should return a non-nil slice")
	}
}
