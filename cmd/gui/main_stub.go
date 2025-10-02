//go:build nogui
// +build nogui

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintf(os.Stderr, "GUI support is disabled in this build. Use the CLI version instead.\n")
	os.Exit(1)
}
