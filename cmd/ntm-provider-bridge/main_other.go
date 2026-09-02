//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "ntm-provider-bridge requires Windows")
	os.Exit(2)
}
