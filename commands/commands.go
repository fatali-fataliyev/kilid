package commands

import (
	"context"

	"github.com/fatali-fataliyev/kilid/handlers"
	"github.com/urfave/cli/v3"
)

func Init() *cli.Command {
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
					&cli.StringFlag{
						Name:    "password",
						Aliases: []string{"p"},
						Usage:   "Password for encryption",
					},
					&cli.StringSliceFlag{
						Name:    "file",
						Aliases: []string{"f"},
						Usage:   "File(s)",
					},
				},

				Action: func(ctx context.Context, cmd *cli.Command) error {
					return handlers.HandleEncryption(cmd.StringSlice("file"), cmd.String("password"))
				},
			},

			// DEC
			{
				Name:    "dec",
				Aliases: []string{"d"},
				Usage:   "Decrypt file(s)",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "password",
						Aliases: []string{"p"},
						Usage:   "Password for decryption [!NOTE: password is case sensitive: myPass != mypass]",
					},

					&cli.StringSliceFlag{
						Name:    "file",
						Aliases: []string{"f"},
						Usage:   "File(s)",
					},
				},

				Action: func(ctx context.Context, cmd *cli.Command) error {
					return handlers.HandleDecryption(cmd.StringSlice("file"), cmd.String("password"))
				},
			},
		},
	}
	return app
}
