package main

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/fatali-fataliyev/kilid/commands"
)

//go:embed version.txt
var version string

func main() {
	fmt.Println("kilid v" + strings.TrimSpace(version))

	cmd := commands.Init()

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		slog.Error(err.Error())
		return
	}
}
