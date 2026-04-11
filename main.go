package main

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/fatali-fataliyev/kilid/v2/commands"
	"github.com/fatali-fataliyev/kilid/v2/engine"
)

//go:embed version.txt
var version string

func main() {
	fmt.Println("KLD v" + strings.TrimSpace(version))
	kld := engine.NewKilid(version)
	cmd := commands.Init(kld)

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		slog.Error(err.Error())
		return
	}
}
