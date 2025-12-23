package main

import (
	"fmt"
	"image"
	"image/png"
	"os"

	"golang.org/x/image/draw"
)

func main() {
	inputPath := "pkg/iconmanager/icon_original.png"
	outputPath := "pkg/iconmanager/icon.png"

	file, err := os.Open(inputPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	img, _, err := image.Decode(file)
	if err != nil {
		panic(err)
	}

	dst := image.NewRGBA(image.Rect(0, 0, 256, 256))
	draw.CatmullRom.Scale(dst, dst.Rect, img, img.Bounds(), draw.Over, nil)

	outFile, err := os.Create(outputPath)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	if err := png.Encode(outFile, dst); err != nil {
		panic(err)
	}
	fmt.Println("Resized icon created at", outputPath)
}
