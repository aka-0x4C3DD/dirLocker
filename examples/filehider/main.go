package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"dirLocker/pkg/filehider"
)

func main() {
	// Create a file hider instance
	hider, err := filehider.NewFileHider()
	if err != nil {
		log.Fatalf("Failed to create file hider: %v", err)
	}

	// Create a temporary test file
	tempDir, err := os.MkdirTemp("", "filehider_example")
	if err != nil {
		log.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "secret.txt")
	testContent := "This is a secret file that will be hidden from the OS!"

	err = os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		log.Fatalf("Failed to create test file: %v", err)
	}

	fmt.Printf("Created test file: %s\n", testFile)
	fmt.Printf("File exists before hiding: %t\n", fileExists(testFile))

	// Hide the file
	fmt.Println("\nHiding the file...")
	err = hider.HideFile(testFile)
	if err != nil {
		log.Fatalf("Failed to hide file: %v", err)
	}

	fmt.Printf("File exists after hiding: %t\n", fileExists(testFile))
	fmt.Printf("File is marked as hidden: %t\n", hider.IsHidden(testFile))

	// List hidden files
	fmt.Println("\nListing hidden files:")
	hiddenFiles, err := hider.ListHidden()
	if err != nil {
		log.Fatalf("Failed to list hidden files: %v", err)
	}

	for i, file := range hiddenFiles {
		fmt.Printf("  %d. %s (hidden at: %s)\n", i+1, file.OriginalPath, file.HiddenAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("     Size: %d bytes, Checksum: %s\n", file.FileSize, file.Checksum[:16]+"...")
	}

	// Unhide the file
	fmt.Println("\nUnhiding the file...")
	fileName := filepath.Base(testFile)
	err = hider.UnhideFile(fileName)
	if err != nil {
		log.Fatalf("Failed to unhide file: %v", err)
	}

	fmt.Printf("File exists after unhiding: %t\n", fileExists(testFile))
	fmt.Printf("File is marked as hidden: %t\n", hider.IsHidden(testFile))

	// Verify content is intact
	restoredContent, err := os.ReadFile(testFile)
	if err != nil {
		log.Fatalf("Failed to read restored file: %v", err)
	}

	fmt.Printf("Content matches original: %t\n", string(restoredContent) == testContent)
	fmt.Println("\nFile hiding example completed successfully!")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
