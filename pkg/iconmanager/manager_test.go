package iconmanager

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createValidICOFile creates a minimal valid ICO file for testing
func createValidICOFile(path string) error {
	// Minimal valid ICO file structure
	icoData := []byte{
		// ICO header
		0x00, 0x00, // Reserved
		0x01, 0x00, // Type (1 = ICO)
		0x01, 0x00, // Number of images

		// Icon directory entry
		0x10,       // Width (16)
		0x10,       // Height (16)
		0x00,       // Color count (0 = no palette)
		0x00,       // Reserved
		0x01, 0x00, // Color planes
		0x20, 0x00, // Bits per pixel (32)
		0x68, 0x04, 0x00, 0x00, // Size of bitmap data (1128 bytes)
		0x16, 0x00, 0x00, 0x00, // Offset to bitmap data (22 bytes)

		// Bitmap data (minimal BITMAPINFOHEADER + pixel data)
		0x28, 0x00, 0x00, 0x00, // Size of BITMAPINFOHEADER (40)
		0x10, 0x00, 0x00, 0x00, // Width
		0x20, 0x00, 0x00, 0x00, // Height (2 * icon height for AND mask)
		0x01, 0x00, // Planes
		0x20, 0x00, // Bits per pixel
		0x00, 0x00, 0x00, 0x00, // Compression
		0x00, 0x00, 0x00, 0x00, // Image size
		0x00, 0x00, 0x00, 0x00, // X pixels per meter
		0x00, 0x00, 0x00, 0x00, // Y pixels per meter
		0x00, 0x00, 0x00, 0x00, // Colors used
		0x00, 0x00, 0x00, 0x00, // Important colors
	}

	// Add minimal pixel data (16x16 pixels * 4 bytes + 16x16 AND mask)
	pixelData := make([]byte, 16*16*4+16*16/8) // RGBA + AND mask
	icoData = append(icoData, pixelData...)

	return ioutil.WriteFile(path, icoData, 0644)
}

// createInvalidICOFile creates an invalid ICO file for testing
func createInvalidICOFile(path string) error {
	// Invalid ICO file (wrong signature)
	invalidData := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}
	return ioutil.WriteFile(path, invalidData, 0644)
}

func TestNewIconManager(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "iconmanager_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := IconManagerConfig{
		AppDir:                tempDir,
		EnableChangeDetection: true,
	}

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	manager := NewIconManager(config, logger)

	assert.NotNil(t, manager)
	assert.Equal(t, tempDir, manager.appDir)
	assert.NotNil(t, manager.defaultIcon)
	assert.Equal(t, logger, manager.logger)
}

func TestDetectCustomIcon_NoIcons(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "iconmanager_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := IconManagerConfig{AppDir: tempDir}
	manager := NewIconManager(config, logrus.New())

	iconPath, err := manager.DetectCustomIcon()
	assert.NoError(t, err)
	assert.Empty(t, iconPath)
}

func TestDetectCustomIcon_SingleValidIcon(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "iconmanager_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a valid ICO file
	iconPath := filepath.Join(tempDir, "app.ico")
	err = createValidICOFile(iconPath)
	require.NoError(t, err)

	config := IconManagerConfig{AppDir: tempDir}
	manager := NewIconManager(config, logrus.New())

	detectedIcon, err := manager.DetectCustomIcon()
	assert.NoError(t, err)
	assert.Equal(t, iconPath, detectedIcon)
}

func TestDetectCustomIcon_SingleInvalidIcon(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "iconmanager_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create an invalid ICO file
	iconPath := filepath.Join(tempDir, "invalid.ico")
	err = createInvalidICOFile(iconPath)
	require.NoError(t, err)

	config := IconManagerConfig{AppDir: tempDir}
	manager := NewIconManager(config, logrus.New())

	detectedIcon, err := manager.DetectCustomIcon()
	assert.NoError(t, err)
	assert.Empty(t, detectedIcon) // Should return empty string for invalid icon
}

func TestDetectCustomIcon_MultipleIcons(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "iconmanager_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create multiple valid ICO files
	icon1Path := filepath.Join(tempDir, "z_last.ico")
	icon2Path := filepath.Join(tempDir, "a_first.ico")
	icon3Path := filepath.Join(tempDir, "m_middle.ico")

	err = createValidICOFile(icon1Path)
	require.NoError(t, err)
	err = createValidICOFile(icon2Path)
	require.NoError(t, err)
	err = createValidICOFile(icon3Path)
	require.NoError(t, err)

	config := IconManagerConfig{AppDir: tempDir}
	manager := NewIconManager(config, logrus.New())

	detectedIcon, err := manager.DetectCustomIcon()
	assert.NoError(t, err)
	// Should select the first one alphabetically
	assert.Equal(t, icon2Path, detectedIcon)
}

func TestHandleMultipleIcons(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "iconmanager_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := IconManagerConfig{AppDir: tempDir}
	manager := NewIconManager(config, logrus.New())

	// Test with empty slice
	_, err = manager.HandleMultipleIcons([]string{})
	assert.Error(t, err)

	// Create test icons
	icon1Path := filepath.Join(tempDir, "z_last.ico")
	icon2Path := filepath.Join(tempDir, "a_first.ico")

	err = createValidICOFile(icon1Path)
	require.NoError(t, err)
	err = createValidICOFile(icon2Path)
	require.NoError(t, err)

	icons := []string{icon1Path, icon2Path}
	selectedIcon, err := manager.HandleMultipleIcons(icons)
	assert.NoError(t, err)
	assert.Equal(t, icon2Path, selectedIcon) // Should select alphabetically first
}

func TestValidateIcon(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "iconmanager_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := IconManagerConfig{AppDir: tempDir}
	manager := NewIconManager(config, logrus.New())

	// Test empty path
	err = manager.ValidateIcon("")
	assert.Error(t, err)

	// Test non-existent file
	err = manager.ValidateIcon(filepath.Join(tempDir, "nonexistent.ico"))
	assert.Error(t, err)

	// Test empty file
	emptyFile := filepath.Join(tempDir, "empty.ico")
	err = ioutil.WriteFile(emptyFile, []byte{}, 0644)
	require.NoError(t, err)
	err = manager.ValidateIcon(emptyFile)
	assert.Error(t, err)

	// Test file too large
	largeFile := filepath.Join(tempDir, "large.ico")
	largeData := make([]byte, 11*1024*1024) // 11MB
	err = ioutil.WriteFile(largeFile, largeData, 0644)
	require.NoError(t, err)
	err = manager.ValidateIcon(largeFile)
	assert.Error(t, err)

	// Test invalid ICO file
	invalidFile := filepath.Join(tempDir, "invalid.ico")
	err = createInvalidICOFile(invalidFile)
	require.NoError(t, err)
	err = manager.ValidateIcon(invalidFile)
	assert.Error(t, err)

	// Test valid ICO file
	validFile := filepath.Join(tempDir, "valid.ico")
	err = createValidICOFile(validFile)
	require.NoError(t, err)
	err = manager.ValidateIcon(validFile)
	assert.NoError(t, err)
}

func TestApplyIcon(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "iconmanager_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := IconManagerConfig{AppDir: tempDir}
	manager := NewIconManager(config, logrus.New())

	// Test applying default icon (empty path)
	err = manager.ApplyIcon("")
	assert.NoError(t, err)
	assert.Empty(t, manager.GetCurrentIcon())

	// Test applying valid icon
	validIcon := filepath.Join(tempDir, "valid.ico")
	err = createValidICOFile(validIcon)
	require.NoError(t, err)

	err = manager.ApplyIcon(validIcon)
	assert.NoError(t, err)
	assert.Equal(t, validIcon, manager.GetCurrentIcon())

	// Test applying invalid icon
	invalidIcon := filepath.Join(tempDir, "invalid.ico")
	err = createInvalidICOFile(invalidIcon)
	require.NoError(t, err)

	err = manager.ApplyIcon(invalidIcon)
	assert.Error(t, err)
	// Current icon should remain unchanged
	assert.Equal(t, validIcon, manager.GetCurrentIcon())
}

func TestGetDefaultIcon(t *testing.T) {
	config := IconManagerConfig{}
	manager := NewIconManager(config, logrus.New())

	defaultIcon := manager.GetDefaultIcon()
	assert.NotNil(t, defaultIcon)
	assert.Greater(t, len(defaultIcon), 0)
}

func TestDetectIconChange(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "iconmanager_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := IconManagerConfig{AppDir: tempDir}
	manager := NewIconManager(config, logrus.New())

	// Test with no current icon - should detect if new icon is added
	changed, err := manager.DetectIconChange()
	assert.NoError(t, err)
	assert.False(t, changed)

	// Add an icon and test detection
	iconPath := filepath.Join(tempDir, "test.ico")
	err = createValidICOFile(iconPath)
	require.NoError(t, err)

	changed, err = manager.DetectIconChange()
	assert.NoError(t, err)
	assert.True(t, changed)

	// Apply the icon
	err = manager.ApplyIcon(iconPath)
	require.NoError(t, err)

	// Should not detect change immediately after applying
	changed, err = manager.DetectIconChange()
	assert.NoError(t, err)
	assert.False(t, changed)

	// Modify the icon file
	time.Sleep(10 * time.Millisecond) // Ensure different modification time
	err = createValidICOFile(iconPath)
	require.NoError(t, err)

	// Should detect the change
	changed, err = manager.DetectIconChange()
	assert.NoError(t, err)
	assert.True(t, changed)

	// Test with deleted icon
	err = os.Remove(iconPath)
	require.NoError(t, err)

	changed, err = manager.DetectIconChange()
	assert.NoError(t, err)
	assert.True(t, changed)
}

func TestGetIconModTime(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "iconmanager_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := IconManagerConfig{AppDir: tempDir}
	manager := NewIconManager(config, logrus.New())

	// Test with empty path
	_, err = manager.GetIconModTime("")
	assert.Error(t, err)

	// Test with non-existent file
	_, err = manager.GetIconModTime(filepath.Join(tempDir, "nonexistent.ico"))
	assert.Error(t, err)

	// Test with valid file
	iconPath := filepath.Join(tempDir, "test.ico")
	err = createValidICOFile(iconPath)
	require.NoError(t, err)

	modTime, err := manager.GetIconModTime(iconPath)
	assert.NoError(t, err)
	assert.False(t, modTime.IsZero())

	// Verify the modification time matches file system
	fileInfo, err := os.Stat(iconPath)
	require.NoError(t, err)
	assert.True(t, modTime.Equal(fileInfo.ModTime()))
}

func TestScanForIcoFiles_SubdirectoriesIgnored(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "iconmanager_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create icon in root directory
	rootIcon := filepath.Join(tempDir, "root.ico")
	err = createValidICOFile(rootIcon)
	require.NoError(t, err)

	// Create subdirectory with icon (should be ignored)
	subDir := filepath.Join(tempDir, "subdir")
	err = os.Mkdir(subDir, 0755)
	require.NoError(t, err)

	subIcon := filepath.Join(subDir, "sub.ico")
	err = createValidICOFile(subIcon)
	require.NoError(t, err)

	config := IconManagerConfig{AppDir: tempDir}
	manager := NewIconManager(config, logrus.New())

	icons, err := manager.scanForIcoFiles()
	assert.NoError(t, err)
	assert.Len(t, icons, 1)
	assert.Equal(t, rootIcon, icons[0])
}

func TestIconManagerIntegration(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "iconmanager_integration")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := IconManagerConfig{
		AppDir:                tempDir,
		EnableChangeDetection: true,
	}

	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel) // Reduce noise in tests

	manager := NewIconManager(config, logger)

	// Test complete workflow
	// 1. No icons initially
	icon, err := manager.DetectCustomIcon()
	assert.NoError(t, err)
	assert.Empty(t, icon)

	// 2. Add an icon
	iconPath := filepath.Join(tempDir, "app.ico")
	err = createValidICOFile(iconPath)
	require.NoError(t, err)

	// 3. Detect the new icon
	icon, err = manager.DetectCustomIcon()
	assert.NoError(t, err)
	assert.Equal(t, iconPath, icon)

	// 4. Apply the icon
	err = manager.ApplyIcon(icon)
	assert.NoError(t, err)
	assert.Equal(t, iconPath, manager.GetCurrentIcon())

	// 5. Verify no change detected immediately
	changed, err := manager.DetectIconChange()
	assert.NoError(t, err)
	assert.False(t, changed)

	// 6. Add another icon (should trigger multiple icon warning)
	icon2Path := filepath.Join(tempDir, "another.ico")
	err = createValidICOFile(icon2Path)
	require.NoError(t, err)

	// 7. Detection should still work and select alphabetically first
	detectedIcon, err := manager.DetectCustomIcon()
	assert.NoError(t, err)
	// "another.ico" comes before "app.ico" alphabetically
	assert.Equal(t, icon2Path, detectedIcon)
}
