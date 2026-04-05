package handlers

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/fatali-fataliyev/kilid/engine"
)

func HandleEncryption(kld *engine.Kilid, files []string, password string, hint string, deleteSource bool, yesAll bool) error {
	ff := resolveFiles(files)

	if len(ff) == 0 {
		return fmt.Errorf("there is no file to encrypt")
	}

	c := 1
	for _, f := range files {
		if err := kld.EncryptFile(f, password, hint, deleteSource, yesAll); err != nil {
			slog.Error("failed to encrypt file", "error", err)
			continue
		}

		fmt.Printf("\n Progress: [%d/%d] (%.0f%%)\n", c, len(ff), (float64(c) / float64(len(ff)) * 100))
		slog.Info(fmt.Sprintf("%q encrypted successfully", f))
		c++
	}

	return nil
}

func HandleDecryption(kld *engine.Kilid, files []string, password string, deleteSource bool, yesAll bool) error {
	ff := resolveFiles(files)

	if len(ff) == 0 {
		return fmt.Errorf("there is no file to decrypt")
	}

	c := 1
	for _, f := range files {
		hint, err := kld.DecryptFile(f, password, deleteSource, yesAll)
		if err != nil {
			fmt.Println() // Ensures slog output starts on a new line after hidden input
			slog.Error("failed to decrypt file", "error", err)
			if strings.Contains(err.Error(), "password") {
				slog.Info(fmt.Sprintf("Password Hint: %q", hint))
			}
			continue
		}

		fmt.Printf("\n Progress: [%d/%d] (%.0f%%)\n", c, len(ff), (float64(c) / float64(len(ff)) * 100))
		slog.Info(fmt.Sprintf("%q decrypted successfully", f))
		c++
	}

	return nil
}

func HandleInfo(kld *engine.Kilid, files []string) error {
	ff := resolveFiles(files)

	if len(ff) == 0 {
		return fmt.Errorf("there is no file to print info")
	}

	c := 1
	for _, f := range ff {
		if err := kld.PrintFileInfo(f); err != nil {
			slog.Error("failed to print file info", "error", err)
			continue
		}

		fmt.Printf("\n Progress: [%d/%d] (%.0f%%)\n", c, len(ff), (float64(c) / float64(len(ff)) * 100))
		c++
	}
	fmt.Println("Note: Dates use the YYYY/MM/DD HH:MM:SS format.")

	return nil
}

func resolveFiles(ff []string) []string {
	var files []string

	for _, f := range ff {
		info, err := os.Stat(strings.TrimSpace(f))
		if os.IsNotExist(err) {
			slog.Error(fmt.Sprintf("%q does not exist", f))
			continue
		}
		if info.IsDir() {
			slog.Error(fmt.Sprintf("%q is a directory, not a file", f))
			continue
		}
		files = append(files, f)
	}

	return files
}
