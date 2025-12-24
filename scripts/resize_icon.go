package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

func main() {
	inputPath := "pkg/iconmanager/icon_original.png"
	// Wails expects appicon.png in the build folder
	wailsIconPath := "cmd/gui/build/appicon.png"
	// Windows ICO path
	icoPath := "cmd/gui/build/windows/icon.ico"
	// Default icon path (for fallback)
	pkgIconPath := "pkg/iconmanager/default_icon.ico"

	// 1. Copy original to Wails appicon.png
	if err := copyFile(inputPath, wailsIconPath); err != nil {
		fmt.Printf("Error copying to %s: %v\n", wailsIconPath, err)
		os.Exit(1)
	}
	fmt.Printf("Generated Wails icon: %s\n", wailsIconPath)

	// 2. Convert to ICO (simple PNG encapsulation for Windows Vista+)
	if err := convertToIco(inputPath, icoPath); err != nil {
		fmt.Printf("Error creating ICO %s: %v\n", icoPath, err)
		os.Exit(1)
	}
	fmt.Printf("Generated Windows ICO: %s\n", icoPath)

	// 3. Copy ICO to pkg/iconmanager for CLI/Wait fallback
	if err := copyFile(icoPath, pkgIconPath); err != nil {
		fmt.Printf("Error copying to %s: %v\n", pkgIconPath, err)
		// Not fatal
	}
	fmt.Printf("Updated default icon: %s\n", pkgIconPath)
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

func convertToIco(pngPath, icoPath string) error {
	pngFile, err := os.Open(pngPath)
	if err != nil {
		return err
	}
	defer pngFile.Close()

	pngInfo, err := pngFile.Stat()
	if err != nil {
		return err
	}
	size := pngInfo.Size()

	icoFile, err := os.Create(icoPath)
	if err != nil {
		return err
	}
	defer icoFile.Close()

	// ICONDIR Header
	// Reserved (2) | Type (2) | Count (2)
	// Type 1 = Icon
	if err := binary.Write(icoFile, binary.LittleEndian, uint16(0)); err != nil {
		return err
	}
	if err := binary.Write(icoFile, binary.LittleEndian, uint16(1)); err != nil {
		return err
	}
	if err := binary.Write(icoFile, binary.LittleEndian, uint16(1)); err != nil {
		return err
	}

	// ICONDIRENTRY
	// Width (1) | Height (1) | ColorCount (1) | Reserved (1) | Planes (2) | BitCount (2) | BytesInRes (4) | ImageOffset (4)
	// 0 means 256 for width/height
	if err := binary.Write(icoFile, binary.LittleEndian, uint8(0)); err != nil {
		return err
	}
	if err := binary.Write(icoFile, binary.LittleEndian, uint8(0)); err != nil {
		return err
	}
	if err := binary.Write(icoFile, binary.LittleEndian, uint8(0)); err != nil {
		return err
	}
	if err := binary.Write(icoFile, binary.LittleEndian, uint8(0)); err != nil {
		return err
	}
	if err := binary.Write(icoFile, binary.LittleEndian, uint16(1)); err != nil {
		return err
	}
	if err := binary.Write(icoFile, binary.LittleEndian, uint16(32)); err != nil {
		return err
	}
	if err := binary.Write(icoFile, binary.LittleEndian, uint32(size)); err != nil {
		return err
	}
	if err := binary.Write(icoFile, binary.LittleEndian, uint32(22)); err != nil {
		return err
	} // Offset = 6 (header) + 16 (entry)

	// Write PNG data
	if _, err := pngFile.Seek(0, 0); err != nil {
		return err
	}
	if _, err := io.Copy(icoFile, pngFile); err != nil {
		return err
	}

	return nil
}
