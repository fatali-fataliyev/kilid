package main

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/fatali-fataliyev/kilid/v3/commands"
	"github.com/fatali-fataliyev/kilid/v3/engine"
)

//go:embed version.txt
var version string

func main() {
	fmt.Println("KLD v" + strings.TrimSpace(version))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	kld := engine.NewKilid(version)

	cmd := commands.Init(ctx, kld)

	if err := cmd.Run(ctx, os.Args); err != nil {
		fmt.Println()
		slog.Error(err.Error())
		return
	}
}
