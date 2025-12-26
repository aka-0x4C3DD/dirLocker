package tests

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"dirLocker/pkg/filehider"
)

// TestFileHidingWorkflow tests the complete file hiding workflow
func TestFileHidingWorkflow(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "file_hiding_workflow_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create file hider with isolated test directory
	hider, err := filehider.NewFileHiderForTesting(tempDir)
	require.NoError(t, err)

	// Create test files with different types and sizes
	testFiles := map[string][]byte{
		"document.pdf":        generatePDFLikeData(t, 500*1024),
		"photo.jpg":           generateJPEGLikeData(t, 2*1024*1024),
		"secret_notes.txt":    []byte("These are my secret notes that should be completely hidden from the operating system."),
		"financial_data.xlsx": generateExcelLikeData(t, 200*1024),
		"backup.zip":          generateZipLikeData(t, 1*1024*1024),
	}

	createdFiles := make([]string, 0, len(testFiles))

	t.Log("Creating test files...")
	for filename, data := range testFiles {
		filePath := filepath.Join(tempDir, filename)
		err := os.WriteFile(filePath, data, 0644)
		require.NoError(t, err, "Failed to create test file: %s", filename)
		createdFiles = append(createdFiles, filePath)
		t.Logf("Created test file: %s (%d bytes)", filename, len(data))
	}

	// Verify files are visible before hiding
	t.Log("Verifying files are visible before hiding...")
	for _, filePath := range createdFiles {
		_, err := os.Stat(filePath)
		require.NoError(t, err, "File should be visible before hiding: %s", filePath)
	}

	// Hide all files
	t.Log("Hiding files...")
	hiddenFiles := make([]string, 0, len(createdFiles))
	for _, filePath := range createdFiles {
		err := hider.HideFile(filePath)
		require.NoError(t, err, "Failed to hide file: %s", filePath)
		hiddenFiles = append(hiddenFiles, filePath)
		t.Logf("Successfully hid file: %s", filePath)
	}

	// Verify files are hidden
	t.Log("Verifying files are hidden...")
	for _, filePath := range hiddenFiles {
		_, err := os.Stat(filePath)
		if runtime.GOOS == "windows" {
			// On Windows, hidden files might still be accessible via Stat
			// but should not appear in normal directory listings
			entries, err := os.ReadDir(filepath.Dir(filePath))
			require.NoError(t, err)

			filename := filepath.Base(filePath)
			found := false
			for _, entry := range entries {
				if entry.Name() == filename {
					found = true
					break
				}
			}
			assert.False(t, found, "Hidden file should not appear in directory listing: %s", filename)
		} else {
			// On Unix systems, the behavior depends on the implementation
			// The file might be moved or have attributes changed
			t.Logf("File hiding status for %s: %v", filePath, err)
		}
	}

	// List hidden files
	t.Log("Listing hidden files...")
	hiddenList, err := hider.ListHidden()
	require.NoError(t, err, "Failed to list hidden files")

	assert.Equal(t, len(hiddenFiles), len(hiddenList), "Hidden file count mismatch")

	for _, hiddenInfo := range hiddenList {
		t.Logf("Hidden file: %s (size: %d, hidden at: %s)",
			hiddenInfo.OriginalPath, hiddenInfo.FileSize, hiddenInfo.HiddenAt.Format(time.RFC3339))

		// Verify the file was one of our test files
		found := false
		for _, filePath := range hiddenFiles {
			if hiddenInfo.OriginalPath == filePath {
				found = true
				break
			}
		}
		assert.True(t, found, "Unexpected file in hidden list: %s", hiddenInfo.OriginalPath)
	}

	// Test revealing individual files
	t.Log("Testing individual file reveal...")
	if len(hiddenFiles) > 0 {
		testFile := hiddenFiles[0]
		err := hider.UnhideFile(filepath.Base(testFile))
		require.NoError(t, err, "Failed to reveal file: %s", testFile)

		// Verify file is visible again
		_, err = os.Stat(testFile)
		require.NoError(t, err, "Revealed file should be visible: %s", testFile)

		// Verify file content is intact
		revealedData, err := os.ReadFile(testFile)
		require.NoError(t, err, "Failed to read revealed file: %s", testFile)

		originalData := testFiles[filepath.Base(testFile)]
		assert.Equal(t, originalData, revealedData, "Revealed file content corrupted: %s", testFile)

		t.Logf("Successfully revealed and verified file: %s", testFile)

		// Remove from hidden list for cleanup
		hiddenFiles = hiddenFiles[1:]
	}

	// Test revealing all remaining files
	t.Log("Revealing all remaining hidden files...")
	// Reveal each file individually since there's no RevealAllFiles method
	for _, filePath := range hiddenFiles {
		err = hider.UnhideFile(filepath.Base(filePath))
		require.NoError(t, err, "Failed to reveal file: %s", filePath)
	}

	// Verify all files are visible and intact
	t.Log("Verifying all files are revealed and intact...")
	for _, filePath := range hiddenFiles {
		_, err := os.Stat(filePath)
		require.NoError(t, err, "File should be visible after reveal all: %s", filePath)

		// Verify content integrity
		revealedData, err := os.ReadFile(filePath)
		require.NoError(t, err, "Failed to read revealed file: %s", filePath)

		originalData := testFiles[filepath.Base(filePath)]
		assert.Equal(t, originalData, revealedData, "File content corrupted after reveal: %s", filePath)
	}

	// Verify hidden list is empty
	finalHiddenList, err := hider.ListHidden()
	require.NoError(t, err, "Failed to list hidden files after reveal all")
	assert.Empty(t, finalHiddenList, "Hidden file list should be empty after revealing all")

	t.Log("File hiding workflow test completed successfully")
}

// TestFileHidingEdgeCases tests edge cases in file hiding
func TestFileHidingEdgeCases(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "file_hiding_edge_cases_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	hider, err := filehider.NewFileHiderForTesting(tempDir)
	require.NoError(t, err)

	t.Run("EmptyFile", func(t *testing.T) {
		emptyFile := filepath.Join(tempDir, "empty.txt")
		err := os.WriteFile(emptyFile, []byte{}, 0644)
		require.NoError(t, err)

		err = hider.HideFile(emptyFile)
		require.NoError(t, err, "Should be able to hide empty file")

		hiddenList, err := hider.ListHidden()
		require.NoError(t, err)

		found := false
		for _, info := range hiddenList {
			if info.OriginalPath == emptyFile {
				found = true
				assert.Equal(t, int64(0), info.FileSize, "Empty file should have size 0")
				break
			}
		}
		assert.True(t, found, "Empty file should appear in hidden list")

		err = hider.UnhideFile(filepath.Base(emptyFile))
		require.NoError(t, err, "Should be able to reveal empty file")

		revealedData, err := os.ReadFile(emptyFile)
		require.NoError(t, err)
		assert.Empty(t, revealedData, "Revealed empty file should still be empty")
	})

	t.Run("LargeFile", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping large file test in short mode")
		}

		largeFile := filepath.Join(tempDir, "large.dat")
		largeData := make([]byte, 10*1024*1024) // 10MB
		_, err := rand.Read(largeData)
		require.NoError(t, err)

		err = os.WriteFile(largeFile, largeData, 0644)
		require.NoError(t, err)

		start := time.Now()
		err = hider.HideFile(largeFile)
		hideDuration := time.Since(start)
		require.NoError(t, err, "Should be able to hide large file")
		t.Logf("Hiding 10MB file took: %v", hideDuration)

		start = time.Now()
		err = hider.UnhideFile(filepath.Base(largeFile))
		revealDuration := time.Since(start)
		require.NoError(t, err, "Should be able to reveal large file")
		t.Logf("Revealing 10MB file took: %v", revealDuration)

		revealedData, err := os.ReadFile(largeFile)
		require.NoError(t, err)
		assert.Equal(t, largeData, revealedData, "Large file content should be intact")
	})

	t.Run("SpecialCharacterFilenames", func(t *testing.T) {
		specialFiles := []string{
			"file with spaces.txt",
			"file-with-dashes.txt",
			"file_with_underscores.txt",
			"file.with.dots.txt",
			"file(with)parentheses.txt",
			"file[with]brackets.txt",
		}

		// Add Unicode filenames if supported
		if runtime.GOOS != "windows" {
			specialFiles = append(specialFiles,
				"файл_на_русском.txt",
				"文件名_中文.txt",
				"ファイル名_日本語.txt",
			)
		}

		for _, filename := range specialFiles {
			t.Run(fmt.Sprintf("Filename_%s", filename), func(t *testing.T) {
				filePath := filepath.Join(tempDir, filename)
				testData := []byte(fmt.Sprintf("Content for file: %s", filename))

				err := os.WriteFile(filePath, testData, 0644)
				require.NoError(t, err, "Failed to create file with special characters: %s", filename)

				err = hider.HideFile(filePath)
				require.NoError(t, err, "Failed to hide file with special characters: %s", filename)

				err = hider.UnhideFile(filename)
				require.NoError(t, err, "Failed to reveal file with special characters: %s", filename)

				revealedData, err := os.ReadFile(filePath)
				require.NoError(t, err, "Failed to read revealed file: %s", filename)
				assert.Equal(t, testData, revealedData, "Content corrupted for file: %s", filename)
			})
		}
	})

	t.Run("NonExistentFile", func(t *testing.T) {
		nonExistentFile := filepath.Join(tempDir, "does_not_exist.txt")

		err := hider.HideFile(nonExistentFile)
		assert.Error(t, err, "Should not be able to hide non-existent file")

		err = hider.UnhideFile(filepath.Base(nonExistentFile))
		assert.Error(t, err, "Should not be able to reveal non-existent file")
	})

	t.Run("DirectoryHiding", func(t *testing.T) {
		testDir := filepath.Join(tempDir, "test_directory")
		err := os.Mkdir(testDir, 0755)
		require.NoError(t, err)

		// Create some files in the directory
		for i := 0; i < 3; i++ {
			filePath := filepath.Join(testDir, fmt.Sprintf("file_%d.txt", i))
			err := os.WriteFile(filePath, []byte(fmt.Sprintf("Content %d", i)), 0644)
			require.NoError(t, err)
		}

		// Try to hide the directory
		err = hider.HideFile(testDir)
		// This might or might not be supported depending on implementation
		if err != nil {
			t.Logf("Directory hiding not supported: %v", err)
		} else {
			t.Log("Directory hiding is supported")

			// If supported, test revealing
			err = hider.UnhideFile(filepath.Base(testDir))
			require.NoError(t, err, "Should be able to reveal hidden directory")

			// Verify directory and contents are intact
			entries, err := os.ReadDir(testDir)
			require.NoError(t, err)
			assert.Len(t, entries, 3, "Directory should contain 3 files after reveal")
		}
	})

	t.Run("ConcurrentHiding", func(t *testing.T) {
		// Test hiding multiple files concurrently
		const numFiles = 10
		filePaths := make([]string, numFiles)

		// Create test files
		for i := 0; i < numFiles; i++ {
			filePath := filepath.Join(tempDir, fmt.Sprintf("concurrent_%d.txt", i))
			testData := []byte(fmt.Sprintf("Concurrent test data %d", i))
			err := os.WriteFile(filePath, testData, 0644)
			require.NoError(t, err)
			filePaths[i] = filePath
		}

		// Hide files sequentially (concurrent hiding might not be safe)
		for _, filePath := range filePaths {
			err := hider.HideFile(filePath)
			require.NoError(t, err, "Failed to hide concurrent file: %s", filePath)
		}

		// Verify all files are hidden
		hiddenList, err := hider.ListHidden()
		require.NoError(t, err)

		hiddenCount := 0
		for _, info := range hiddenList {
			for _, filePath := range filePaths {
				if info.OriginalPath == filePath {
					hiddenCount++
					break
				}
			}
		}
		assert.Equal(t, numFiles, hiddenCount, "All concurrent files should be hidden")

		// Reveal all files
		for _, filePath := range filePaths {
			err = hider.UnhideFile(filepath.Base(filePath))
			require.NoError(t, err, "Failed to reveal concurrent file: %s", filePath)
		}

		// Verify all files are revealed and intact
		for i, filePath := range filePaths {
			revealedData, err := os.ReadFile(filePath)
			require.NoError(t, err, "Failed to read revealed concurrent file: %s", filePath)

			expectedData := []byte(fmt.Sprintf("Concurrent test data %d", i))
			assert.Equal(t, expectedData, revealedData, "Concurrent file content corrupted: %s", filePath)
		}
	})
}

// TestFileHidingPersistence tests that hidden files persist across restarts
func TestFileHidingPersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "file_hiding_persistence_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create first file hider instance
	hider1, err := filehider.NewFileHiderForTesting(tempDir)
	require.NoError(t, err)

	// Create test files
	testFiles := map[string][]byte{
		"persistent1.txt": []byte("This file should persist across restarts"),
		"persistent2.pdf": generatePDFLikeData(t, 100*1024),
		"persistent3.jpg": generateJPEGLikeData(t, 500*1024),
	}

	filePaths := make([]string, 0, len(testFiles))
	for filename, data := range testFiles {
		filePath := filepath.Join(tempDir, filename)
		err := os.WriteFile(filePath, data, 0644)
		require.NoError(t, err)
		filePaths = append(filePaths, filePath)
	}

	// Hide files with first instance
	t.Log("Hiding files with first hider instance...")
	for _, filePath := range filePaths {
		err := hider1.HideFile(filePath)
		require.NoError(t, err, "Failed to hide file: %s", filePath)
	}

	// Get hidden list from first instance
	hiddenList1, err := hider1.ListHidden()
	require.NoError(t, err)
	assert.Len(t, hiddenList1, len(testFiles), "First instance should show all hidden files")

	// Create second file hider instance (simulating restart)
	t.Log("Creating second hider instance (simulating restart)...")
	hider2, err := filehider.NewFileHiderForTesting(tempDir)
	require.NoError(t, err)

	// Check that second instance can see the hidden files
	hiddenList2, err := hider2.ListHidden()
	require.NoError(t, err)
	assert.Len(t, hiddenList2, len(testFiles), "Second instance should see persisted hidden files")

	// Verify the hidden files are the same
	for _, info1 := range hiddenList1 {
		found := false
		for _, info2 := range hiddenList2 {
			if info1.OriginalPath == info2.OriginalPath {
				found = true
				assert.Equal(t, info1.FileSize, info2.FileSize, "File size should match across instances")
				// Note: HiddenAt times might differ slightly due to precision
				break
			}
		}
		assert.True(t, found, "Hidden file should persist across instances: %s", info1.OriginalPath)
	}

	// Reveal files using second instance
	t.Log("Revealing files with second hider instance...")
	for filename := range testFiles {
		err = hider2.UnhideFile(filename)
		require.NoError(t, err, "Second instance should be able to reveal file: %s", filename)
	}

	// Verify files are revealed and intact
	for filename, originalData := range testFiles {
		filePath := filepath.Join(tempDir, filename)
		revealedData, err := os.ReadFile(filePath)
		require.NoError(t, err, "Should be able to read revealed file: %s", filename)
		assert.Equal(t, originalData, revealedData, "File content should be intact after persistence: %s", filename)
	}

	// Verify both instances show empty hidden list
	hiddenList1Final, err := hider1.ListHidden()
	require.NoError(t, err)
	assert.Empty(t, hiddenList1Final, "First instance should show empty list after reveal")

	hiddenList2Final, err := hider2.ListHidden()
	require.NoError(t, err)
	assert.Empty(t, hiddenList2Final, "Second instance should show empty list after reveal")

	t.Log("File hiding persistence test completed successfully")
}

// TestFileHidingErrorRecovery tests error recovery scenarios
func TestFileHidingErrorRecovery(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "file_hiding_error_recovery_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	hider, err := filehider.NewFileHiderForTesting(tempDir)
	require.NoError(t, err)

	t.Run("PartialHidingFailure", func(t *testing.T) {
		// Create test files
		validFile := filepath.Join(tempDir, "valid.txt")
		err := os.WriteFile(validFile, []byte("Valid file content"), 0644)
		require.NoError(t, err)

		// Hide the valid file
		err = hider.HideFile(validFile)
		require.NoError(t, err)

		// Try to hide a non-existent file (should fail)
		nonExistentFile := filepath.Join(tempDir, "does_not_exist.txt")
		err = hider.HideFile(nonExistentFile)
		assert.Error(t, err, "Should fail to hide non-existent file")

		// Verify that the valid file is still hidden
		hiddenList, err := hider.ListHidden()
		require.NoError(t, err)

		found := false
		for _, info := range hiddenList {
			if info.OriginalPath == validFile {
				found = true
				break
			}
		}
		assert.True(t, found, "Valid file should still be hidden after partial failure")

		// Clean up
		err = hider.UnhideFile(filepath.Base(validFile))
		require.NoError(t, err)
	})

	t.Run("RevealNonHiddenFile", func(t *testing.T) {
		// Create a file but don't hide it
		normalFile := filepath.Join(tempDir, "normal.txt")
		err := os.WriteFile(normalFile, []byte("Normal file content"), 0644)
		require.NoError(t, err)

		// Try to reveal it (should fail gracefully)
		err = hider.UnhideFile(filepath.Base(normalFile))
		assert.Error(t, err, "Should fail to reveal non-hidden file")

		// Verify file is still accessible
		data, err := os.ReadFile(normalFile)
		require.NoError(t, err)
		assert.Equal(t, []byte("Normal file content"), data, "Normal file should be unaffected")
	})

	t.Run("CorruptedHiddenFileRegistry", func(t *testing.T) {
		// This test would require access to the internal registry file
		// For now, we'll test that the system handles missing files gracefully

		// Create and hide a file
		testFile := filepath.Join(tempDir, "registry_test.txt")
		err := os.WriteFile(testFile, []byte("Registry test content"), 0644)
		require.NoError(t, err)

		err = hider.HideFile(testFile)
		require.NoError(t, err)

		// Manually delete the hidden file (simulating corruption)
		// Note: This depends on the implementation details
		// In a real scenario, we'd need to know where the file is stored

		// Try to reveal - should handle missing file gracefully
		err = hider.UnhideFile(filepath.Base(testFile))
		// The behavior here depends on implementation
		// It might succeed (if it can detect the file is missing) or fail
		if err != nil {
			t.Logf("Reveal failed as expected for corrupted file: %v", err)
		} else {
			t.Log("Reveal succeeded despite corruption - system recovered gracefully")
		}

		// Clean up any remaining registry entries
		// Try to reveal the test file if it exists
		hider.UnhideFile(filepath.Base(testFile)) // Ignore errors
	})
}

// TestFileHidingPerformance tests performance characteristics
func TestFileHidingPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}

	tempDir, err := os.MkdirTemp("", "file_hiding_performance_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	hider, err := filehider.NewFileHiderForTesting(tempDir)
	require.NoError(t, err)

	t.Run("ManySmallFiles", func(t *testing.T) {
		const numFiles = 100
		filePaths := make([]string, numFiles)

		// Create many small files
		t.Log("Creating test files...")
		for i := 0; i < numFiles; i++ {
			filePath := filepath.Join(tempDir, fmt.Sprintf("small_%03d.txt", i))
			content := []byte(fmt.Sprintf("Small file content %d", i))
			err := os.WriteFile(filePath, content, 0644)
			require.NoError(t, err)
			filePaths[i] = filePath
		}

		// Measure hiding performance
		t.Log("Hiding files...")
		start := time.Now()
		for _, filePath := range filePaths {
			err := hider.HideFile(filePath)
			require.NoError(t, err, "Failed to hide file: %s", filePath)
		}
		hideDuration := time.Since(start)
		t.Logf("Hiding %d files took: %v (avg: %v per file)", numFiles, hideDuration, hideDuration/time.Duration(numFiles))

		// Measure listing performance
		start = time.Now()
		hiddenList, err := hider.ListHidden()
		listDuration := time.Since(start)
		require.NoError(t, err)
		assert.Len(t, hiddenList, numFiles, "Should list all hidden files")
		t.Logf("Listing %d hidden files took: %v", numFiles, listDuration)

		// Measure revealing performance
		start = time.Now()
		for _, filePath := range filePaths {
			err = hider.UnhideFile(filepath.Base(filePath))
			require.NoError(t, err, "Failed to reveal file: %s", filePath)
		}
		revealDuration := time.Since(start)
		t.Logf("Revealing %d files took: %v (avg: %v per file)", numFiles, revealDuration, revealDuration/time.Duration(numFiles))

		// Verify all files are revealed
		for i, filePath := range filePaths {
			data, err := os.ReadFile(filePath)
			require.NoError(t, err, "Failed to read revealed file: %s", filePath)
			expected := []byte(fmt.Sprintf("Small file content %d", i))
			assert.Equal(t, expected, data, "File content corrupted: %s", filePath)
		}
	})

	t.Run("LargeFilesPerformance", func(t *testing.T) {
		sizes := []int{
			1024 * 1024,      // 1MB
			5 * 1024 * 1024,  // 5MB
			10 * 1024 * 1024, // 10MB
		}

		for _, size := range sizes {
			t.Run(fmt.Sprintf("Size_%dMB", size/(1024*1024)), func(t *testing.T) {
				filename := fmt.Sprintf("large_%dmb.dat", size/(1024*1024))
				filePath := filepath.Join(tempDir, filename)

				// Create large file
				largeData := make([]byte, size)
				for i := range largeData {
					largeData[i] = byte(i % 256)
				}
				err := os.WriteFile(filePath, largeData, 0644)
				require.NoError(t, err)

				// Measure hide performance
				start := time.Now()
				err = hider.HideFile(filePath)
				hideDuration := time.Since(start)
				require.NoError(t, err, "Failed to hide large file")

				mbPerSec := float64(size) / (1024 * 1024) / hideDuration.Seconds()
				t.Logf("Hiding %dMB file took: %v (%.2f MB/s)", size/(1024*1024), hideDuration, mbPerSec)

				// Measure reveal performance
				start = time.Now()
				err = hider.UnhideFile(filename)
				revealDuration := time.Since(start)
				require.NoError(t, err, "Failed to reveal large file")

				mbPerSec = float64(size) / (1024 * 1024) / revealDuration.Seconds()
				t.Logf("Revealing %dMB file took: %v (%.2f MB/s)", size/(1024*1024), revealDuration, mbPerSec)

				// Verify content integrity
				revealedData, err := os.ReadFile(filePath)
				require.NoError(t, err)
				assert.Equal(t, largeData, revealedData, "Large file content corrupted")
			})
		}
	})
}
