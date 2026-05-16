package handlers

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fatali-fataliyev/kilid/v3/engine"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

type failCounter struct {
	mu    sync.Mutex
	fails []error
}

func (c *failCounter) AddFail(fail error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fails = append(c.fails, fail)
}

func HandleEncryption(kld *engine.Kilid, files []string, password string, hint string, wipeSrc bool, deleteSrc bool, yesAll bool) error {
	ff := resolveFiles(files)
	if len(ff) == 0 {
		return fmt.Errorf("no files to encrypt")
	}

	var wg sync.WaitGroup
	var failContainer failCounter

	p := mpb.New(mpb.WithWaitGroup(&wg), mpb.WithWidth(60))
	wg.Add(len(ff))

	for _, f := range ff {
		var cancel bool
		func() {
			if yesAll {
				return
			}

			f := kld.GetFileName(f) + ".kld"
			if isFileExistsAlready(f) {
				fmt.Println()
				slog.Warn(fmt.Sprintf("%q already exists, overwrite? [y/n]", f))
				answer := askYN()
				if answer == "y" {
					return
				}
				cancel = true
			}
		}()
		if cancel {
			continue
		}

		info, err := os.Stat(f)
		if err != nil {
			slog.Error("failed to get file info", "file", f, "error", err)
			continue
		}

		bar := p.New(int64(info.Size()),
			mpb.BarStyle().Lbound("[").Filler("*").Tip("*").Padding(".").Rbound("]"),

			mpb.PrependDecorators(
				decor.Name(f),
				decor.Percentage(decor.WCSyncSpace),
			),

			mpb.AppendDecorators(
				decor.OnComplete(
					decor.AverageETA(decor.ET_STYLE_GO, decor.WCSyncWidth), "done",
				),
			),
		)

		go func(file string, b *mpb.Bar) {
			defer wg.Done()

			if err := kld.EncryptFile(file, password, hint, deleteSrc, yesAll, func(n int) { b.IncrBy(n) }); err != nil {
				failContainer.AddFail(fmt.Errorf("Encryption failed: file: %q | error: %w", file, err))
				defer b.Abort(true)

				fileName := kld.GetFileName(file) + ".kld"
				if ensureFileExist(fileName) {
					if err := os.Remove(fileName); err != nil {
						failContainer.AddFail(fmt.Errorf("failed to remove unsuccessful encryption file: %q | error: %w", file, err))
					}
				}
			}
		}(f, bar)
	}

	p.Wait()

	summarizeEncResults(len(ff), failContainer.fails)

	if wipeSrc {
		HandleWiping(kld, ff)
	}

	return nil
}

func HandleWiping(kld *engine.Kilid, files []string) {
	fmt.Println()
	bannerWidth := 45
	text := " === [ WIPING... ] === "

	padding := (bannerWidth - len(text)) / 2
	fmt.Println(strings.Repeat("X", bannerWidth))
	fmt.Println(strings.Repeat(" ", padding) + text)
	fmt.Println(strings.Repeat("X", bannerWidth))

	var wg sync.WaitGroup
	var failContainer failCounter

	p := mpb.New(mpb.WithWaitGroup(&wg), mpb.WithWidth(64))
	wg.Add(len(files))

	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			failContainer.AddFail(fmt.Errorf("failed to get file info: %w", err))
			continue
		}

		bar := p.New(int64(info.Size()),
			mpb.BarStyle().Lbound("[").Filler("#").Tip("#").Padding(".").Rbound("]"),

			mpb.PrependDecorators(
				decor.Name(f),
				decor.Percentage(decor.WCSyncSpace),
			),

			mpb.AppendDecorators(
				decor.OnComplete(
					decor.AverageETA(decor.ET_STYLE_GO, decor.WCSyncWidth), "done",
				),
			),
		)

		go func(file string, b *mpb.Bar) {
			defer wg.Done()
			if err := kld.WipeFile(file, func(n int) { b.IncrBy(n) }); err != nil {
				defer b.Abort(true)
				failContainer.AddFail(fmt.Errorf("failed to wipe %q: %w", file, err))
			}
		}(f, bar)
	}

	p.Wait()

	summarizeWipeResults(len(files), failContainer.fails)
}

func HandleDecryption(kld *engine.Kilid, files []string, password string, deleteSource bool, yesAll bool) error {
	ff := resolveFiles(files)
	if len(ff) == 0 {
		return fmt.Errorf("no files to decrypt")
	}

	var wg sync.WaitGroup
	var failContainer failCounter

	p := mpb.New(mpb.WithWaitGroup(&wg), mpb.WithWidth(60))
	wg.Add(len(ff))

	for _, f := range ff {
		var extGetfail error
		var cancel bool
		func() {
			if yesAll {
				return
			}
			ext, err := kld.GetFileRealExt(f)
			if err != nil {
				extGetfail = err
				return
			}
			f := kld.GetFileName(f) + ext
			if isFileExistsAlready(f) {
				fmt.Println()
				slog.Warn(fmt.Sprintf("%q already exists, overwrite? [y/n]", f))
				answer := askYN()
				if answer == "y" {
					return
				}
				cancel = true
			}
		}()

		if cancel {
			continue
		}
		if extGetfail != nil {
			slog.Error("failed to get original file extension", "file", f, "error", extGetfail)
			continue
		}

		info, err := os.Stat(f)
		if err != nil {
			slog.Error("failed to get file info", "file", f, "error", err)
			continue
		}

		bar := p.New(int64(info.Size()),
			mpb.BarStyle().Lbound("[").Filler("*").Tip("*").Padding(".").Rbound("]"),

			mpb.PrependDecorators(
				decor.Name(f),
				decor.Percentage(decor.WCSyncSpace),
			),

			mpb.AppendDecorators(
				decor.OnComplete(
					decor.AverageETA(decor.ET_STYLE_GO, decor.WCSyncWidth), "done",
				),
			),
		)

		go func(file string, b *mpb.Bar) {
			defer wg.Done()

			if err := kld.DecryptFile(file, password, deleteSource, yesAll, func(n int) { b.IncrBy(n) }); err != nil {
				failContainer.AddFail(fmt.Errorf("Decryption failed: file: %q | error: %w", file, err))
				defer b.Abort(true)

				ext, extErr := kld.GetFileRealExt(file)
				if extErr != nil {
					failContainer.AddFail(fmt.Errorf("failed to get real file extension:  file: %q | error: %w", file, extErr))
					return
				}

				fileName := kld.GetFileName(file) + ext
				if ensureFileExist(fileName) {
					if err := os.Remove(fileName); err != nil {
						failContainer.AddFail(fmt.Errorf("failed to remove unsuccessful decryption file:  file: %q | error: %w", file, err))
					}
				}
			}
		}(f, bar)
	}

	p.Wait()

	summarizeDecResults(len(ff), failContainer.fails)

	return nil
}

func HandleInfo(kld *engine.Kilid, files []string, output *string) error {
	ff := resolveFiles(files)

	if len(ff) == 0 {
		return fmt.Errorf("there is no file to print info")
	}

	var outputSrc *os.File

	if output != nil {
		if filepath.Ext(*output) != ".txt" {
			return fmt.Errorf("only .txt files are supported for output.")
		}

		if err := os.MkdirAll(filepath.Dir(*output), 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		src, err := os.OpenFile(*output, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("failed to open file: %w", err)
		}
		outputSrc = src
	}

	c := 1
	for _, f := range ff {
		info, err := kld.Info(f)
		if err != nil {
			slog.Error("failed to print file info", "error", err)
			continue
		}

		fmt.Printf("\n─── File Details: %s ───\n", f)
		fmt.Printf("%-20s : %s\n", "Original Extension", info.OriginalExtension)
		fmt.Printf("%-20s : %s\n", "Password Hint", info.PasswordHint)
		fmt.Printf("%-20s : %s\n", "Encrypted At", info.Date)
		fmt.Printf("%-20s : %v\n", "Kilid Version", info.Version)
		fmt.Println(strings.Repeat("─", 45))

		if outputSrc != nil {
			var data string

			data = fmt.Sprintf("\n─── File Details: %s ───\n", f)
			if _, err := outputSrc.Write([]byte(data)); err != nil {
				return fmt.Errorf("failed to save file (%s) info: %w", f, err)
			}

			data = fmt.Sprintf("%-20s : %s\n", "Original Extension", info.OriginalExtension)
			if _, err := outputSrc.Write([]byte(data)); err != nil {
				return fmt.Errorf("failed to save file (%s) info: %w", f, err)
			}

			data = fmt.Sprintf("%-20s : %s\n", "Password Hint", info.PasswordHint)
			if _, err := outputSrc.Write([]byte(data)); err != nil {
				return fmt.Errorf("failed to save file (%s) info: %w", f, err)
			}

			data = fmt.Sprintf("%-20s : %s\n", "Encrypted At", info.Date)
			if _, err := outputSrc.Write([]byte(data)); err != nil {
				return fmt.Errorf("failed to save file (%s) info: %w", f, err)
			}

			data = fmt.Sprintf("%-20s : %v\n", "Kilid Version", info.Version)
			if _, err := outputSrc.Write([]byte(data)); err != nil {
				return fmt.Errorf("failed to save file (%s) info: %w", f, err)
			}

			data = strings.Repeat("─", 45)
			if _, err := outputSrc.Write([]byte(data)); err != nil {
				return fmt.Errorf("failed to save file (%s) info: %w", f, err)
			}

			if _, err := outputSrc.Write([]byte("\n")); err != nil {
				return fmt.Errorf("failed to save file (%s) info: %w", f, err)
			}

			outputSrc.Close()
		}

		fmt.Printf("\n Progress: [%d/%d] (%.0f%%) \n\n", c, len(ff), (float64(c) / float64(len(ff)) * 100))
		c++
	}
	if output != nil {
		slog.Info("output results saved", slog.String("path", *output))
	}
	fmt.Println("\nNote: Dates use the YYYY/MM/DD HH:MM:SS format.")

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

func askYN() string {
	var answer string
	fmt.Scanln(&answer)
	answer = strings.TrimSpace(answer)
	answer = strings.ToLower(answer)

	return answer
}

func isFileExistsAlready(fileName string) bool {
	i, err := os.Stat(fileName)
	if err == nil && !i.IsDir() {
		return true
	}
	return false
}

func summarizeEncResults(filesLen int, fails []error) {
	if len(fails) > 0 {
		fmt.Println()
		slog.Error(fmt.Sprintf("Fails(fail/total): %d / %d", len(fails), filesLen))
		fmt.Println()
		fmt.Print(strings.Repeat("─", 20))
		fmt.Print("[ Failures ]")
		fmt.Print(strings.Repeat("─", 20))
		fmt.Println("\n")

		for _, err := range fails {
			slog.Error(err.Error())
		}
		return
	}

	if filesLen == 1 {
		slog.Info("file encrypted successfully")
		return
	}
	slog.Info(fmt.Sprintf("all (%d) files encrypted successfully", filesLen))
}

func ensureFileExist(file string) bool {
	_, err := os.Stat(file)
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	return false
}

func summarizeDecResults(filesLen int, fails []error) {
	if len(fails) > 0 {
		fmt.Println()
		slog.Error(fmt.Sprintf("Fails(fail/total): %d / %d", len(fails), filesLen))
		fmt.Println()
		fmt.Print(strings.Repeat("─", 20))
		fmt.Print("[ Failures ]")
		fmt.Print(strings.Repeat("─", 20))
		fmt.Println("\n")

		for _, err := range fails {
			slog.Error(err.Error())
		}
		return
	}

	if filesLen == 1 {
		slog.Info("file decrypted successfully")
		return
	}
	slog.Info(fmt.Sprintf("all (%d) files decrypted successfully", filesLen))
}

func summarizeWipeResults(filesLen int, fails []error) {
	if len(fails) > 0 {
		fmt.Println()
		slog.Error(fmt.Sprintf("Wipe Fails(fail/total): %d / %d", len(fails), filesLen))
		fmt.Println()
		fmt.Print(strings.Repeat("─", 20))
		fmt.Print("[ Wipe Failures ]")
		fmt.Print(strings.Repeat("─", 20))
		fmt.Println("\n")

		for _, err := range fails {
			slog.Error(err.Error())
		}
		return
	}

	slog.Info(fmt.Sprintf("all (%d) files wiped successfully", filesLen))
}
