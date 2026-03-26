package main

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed version.txt
var version string

func main() {
	fmt.Println("kilid v" + strings.TrimSpace(version))

	fmt.Println("Hello KILID!")
}
