package commands

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/fatali-fataliyev/kilid/engine"
	"github.com/fatali-fataliyev/kilid/handlers"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

func Init(kld *engine.Kilid) *cli.Command {
	app := &cli.Command{
		Name:  "kld",
		Usage: "Encrypt & Decrypt your files with Kilid.",
		Commands: []*cli.Command{
			//ENC
			{
				Name:    "enc",
				Aliases: []string{"e"},
				Usage:   "Encrypt file(s)",
				Arguments: []cli.Argument{&cli.StringArgs{
					Name: "files",
					Max:  -1,
					Min:  1,
				}},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					var password string
					var hint string
					files := cmd.StringArgs("files")

					scanner := bufio.NewScanner(os.Stdin)

					print("Password: ")
					bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
					if err != nil {
						return fmt.Errorf("failed to get password")
					}
					password = string(bytePassword)

					print("\nHint (e.g first dog): ")
					scanner.Scan()
					hint = scanner.Text()

					return handlers.HandleEncryption(kld, files, password, hint)
				},
			},

			// DEC
			{
				Name:    "dec",
				Aliases: []string{"d"},
				Usage:   "Decrypt file(s)",
				Arguments: []cli.Argument{&cli.StringArgs{
					Name: "files",
					Max:  -1,
					Min:  1,
				}},

				Action: func(ctx context.Context, cmd *cli.Command) error {
					var password string
					files := cmd.StringArgs("files")

					print("Password: ")
					bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
					if err != nil {
						return fmt.Errorf("failed to get password")
					}
					password = string(bytePassword)

					return handlers.HandleDecryption(kld, files, password)
				},
			},
		},
	}
	return app
}
