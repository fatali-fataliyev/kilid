package commands

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/fatali-fataliyev/kilid/v3/engine"
	"github.com/fatali-fataliyev/kilid/v3/handlers"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

// TODO:
// 		1. Infos should be write to a file via `-output` flag and user can be provide custom path and file name like this: /path/to/my/file.txt
// 		2. Wipe functionality, should support go routines, like enc and dec commands.
// 		3. Update Go.mod, changelog, readme, build.sh (change to kilid not kld), thats it for now.

func Init(kld *engine.Kilid) *cli.Command {
	app := &cli.Command{
		Name:  "kilid",
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
					&cli.BoolFlag{
						Name:  "wipe",
						Usage: "Shreds source file to prevent recovery",
					},
				},
				Arguments: []cli.Argument{&cli.StringArgs{
					Name: "files",
					Max:  -1,
					Min:  1,
				}},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					var password string
					var confirmPassword string
					var hint string
					files := cmd.StringArgs("files")
					deleteSrc := cmd.Bool("delete")
					wipeSrc := cmd.Bool("wipe")
					yesAll := cmd.Bool("yes")
					scanner := bufio.NewScanner(os.Stdin)

					if deleteSrc && wipeSrc {
						return fmt.Errorf("you cannot pass 'delete source'(-delete) and 'wipe source'(-wipe) at the same time, use one of them")
					}

					print("Password: ")
					b, err := term.ReadPassword(int(os.Stdin.Fd()))
					if err != nil {
						return fmt.Errorf("failed to get password")
					}
					password = string(b)

					print("\nConfirm password: ")
					n, err := term.ReadPassword(int(os.Stdin.Fd()))
					if err != nil {
						return fmt.Errorf("failed to get confirm password: %w", err)
					}
					confirmPassword = string(n)

					if confirmPassword != password {
						return fmt.Errorf("passwords do not match")
					}

					print("\nHint (e.g first dog): ")
					scanner.Scan()
					hint = scanner.Text()
					fmt.Println()
					return handlers.HandleEncryption(kld, files, password, hint, wipeSrc, deleteSrc, yesAll)
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
					deleteSrc := cmd.Bool("delete")
					yesAll := cmd.Bool("yes")

					print("Password: ")
					bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
					if err != nil {
						return fmt.Errorf("failed to get password")
					}
					password = string(bytePassword)
					fmt.Println()
					return handlers.HandleDecryption(kld, files, password, deleteSrc, yesAll)
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
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "output",
						Usage: "path to save info data, example: --output=folder/to/info.txt",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.IsSet("output") {
						fmt.Println("FROM FLAG")
						output := cmd.StringArg("output")
						fmt.Println("output is SET, value: ", output)
						fmt.Println(&output)
						adr := &output
						fmt.Println("value of addr", adr, "is: ", *adr)
						os.Exit(1)
						return handlers.HandleInfo(kld, cmd.StringArgs("files"), &output)
					}
					return handlers.HandleInfo(kld, cmd.StringArgs("files"), nil)
				},
			},

			{
				Name:    "version",
				Aliases: []string{"v"},
				Usage:   "Show Kilid version",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					fmt.Println("Version", kld.Version)
					return nil
				},
			},
		},
	}
	return app
}
