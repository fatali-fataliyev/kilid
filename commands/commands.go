package commands

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/fatali-fataliyev/kilid/v2/engine"
	"github.com/fatali-fataliyev/kilid/v2/handlers"
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
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "delete",
						Aliases: []string{"d"},
						Usage:   "Deletes source file",
					},
					&cli.BoolFlag{
						Name:    "yes",
						Aliases: []string{"y"},
						Usage:   "Answer 'yes' to all prompts, [!]: existing files will be overwritten",
					},
				},
				Arguments: []cli.Argument{&cli.StringArgs{
					Name: "files",
					Max:  -1,
					Min:  1,
				}},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					var password string
					var hint string
					files := cmd.StringArgs("files")
					deleteSource := cmd.Bool("delete")
					yesAll := cmd.Bool("yes")
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
					fmt.Println()
					return handlers.HandleEncryption(kld, files, password, hint, deleteSource, yesAll)
				},
			},

			// DEC
			{
				Name:    "dec",
				Aliases: []string{"d"},
				Usage:   "Decrypt file(s)",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "delete",
						Aliases: []string{"d"},
						Usage:   "Deletes source file",
					},
					&cli.BoolFlag{
						Name:    "yes",
						Aliases: []string{"y"},
						Usage:   "Answer 'yes' to all prompts. [!] existing files will be overwritten",
					},
				},
				Arguments: []cli.Argument{&cli.StringArgs{
					Name: "files",
					Max:  -1,
					Min:  1,
				}},

				Action: func(ctx context.Context, cmd *cli.Command) error {
					var password string
					files := cmd.StringArgs("files")
					deleteSource := cmd.Bool("delete")
					yesAll := cmd.Bool("yes")

					print("Password: ")
					bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
					if err != nil {
						return fmt.Errorf("failed to get password")
					}
					password = string(bytePassword)
					fmt.Println()
					return handlers.HandleDecryption(kld, files, password, deleteSource, yesAll)
				},
			},

			// INFO
			{
				Name:    "info",
				Aliases: []string{"i"},
				Usage:   "Show metadata and details for .kld files",
				Arguments: []cli.Argument{
					&cli.StringArgs{
						Name: "files",
						Max:  -1,
						Min:  1,
					}},

				Action: func(ctx context.Context, cmd *cli.Command) error {
					return handlers.HandleInfo(kld, cmd.StringArgs("files"))
				},
			},
		},
	}
	return app
}
