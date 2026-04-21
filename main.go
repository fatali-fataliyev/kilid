package main

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/fatali-fataliyev/kilid/v2/commands"
	"github.com/fatali-fataliyev/kilid/v2/config"
	"github.com/fatali-fataliyev/kilid/v2/engine"
)

//go:embed version.txt
var version string

func main() {
	fmt.Println("KLD v" + strings.TrimSpace(version))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load argon config", "error", err.Error())
		return
	}

	kld := engine.NewKilid(version, cfg)

	cmd := commands.Init(kld)

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Println()
		slog.Error(err.Error())
		return
	}
}
