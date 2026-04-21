package handlers

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/fatali-fataliyev/kilid/v3/engine"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

func HandleEncryption(kld *engine.Kilid, files []string, password string, hint string, deleteSource bool, yesAll bool) error {
	ff := resolveFiles(files)
	if len(ff) == 0 {
		return fmt.Errorf("no files to encrypt")
	}

	fmt.Println("file: ", ff, len(ff))

	var fails int32
	var p *mpb.Progress

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

		p = mpb.New(mpb.WithWidth(64))
		info, _ := os.Stat(f)
		bar := p.AddBar(info.Size(),
			mpb.PrependDecorators(decor.Name(filepath.Base(f))),
			mpb.AppendDecorators(decor.CountersKibiByte("% .2f / % .2f - "), decor.Percentage()),
		)

		go func(file string, b *mpb.Bar) {
			err := kld.EncryptFile(file, password, hint, deleteSource, yesAll, func(n int) {
				b.IncrBy(n)
			})

			if err != nil {
				atomic.AddInt32(&fails, 1)
				slog.Error("Encryption failed", "file", file, "err", err)
				b.Abort(false)
			}
		}(f, bar)
	}

	if p != nil {
		p.Wait()
	}
	if fails > 0 {
		slog.Info(fmt.Sprintf("%d / %d", fails, len(ff)))
		return nil
	}
	fmt.Println("All done")
	return nil
}

func HandleDecryption(kld *engine.Kilid, files []string, password string, deleteSource bool, yesAll bool) error {
	ff := resolveFiles(files)
	if len(ff) == 0 {
		return fmt.Errorf("no files to decrypt")
	}

	var p *mpb.Progress
	var fails int32

	for _, f := range ff {
		var cancel bool
		func() {
			if yesAll {
				return
			}
			ext, err := kld.Info(f, true)
			if err != nil {
				slog.Error("failed to get extension", "file", f)
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

		p = mpb.New(mpb.WithWidth(64))
		info, _ := os.Stat(f)
		bar := p.AddBar(info.Size(),
			mpb.PrependDecorators(decor.Name(filepath.Base(f))),
			mpb.AppendDecorators(decor.CountersKibiByte("% .2f / % .2f - "), decor.Percentage()),
		)

		go func(file string, b *mpb.Bar) {
			err := kld.DecryptFile(file, password, deleteSource, yesAll, func(n int) {
				b.IncrBy(n)
			})

			if len(err) > 0 {
				atomic.AddInt32(&fails, 1)
				for _, e := range err {
					slog.Error("Decryption failed", "file", file, "err", e)
					b.Abort(false)
				}
			}
		}(f, bar)
	}

	if p != nil {
		p.Wait()
	}
	if fails > 0 {
		slog.Info(fmt.Sprintf("%d / %d", fails, len(ff)))
		return nil
	}
	fmt.Println("All done")
	return nil
}

func HandleInfo(kld *engine.Kilid, files []string) error {
	ff := resolveFiles(files)

	if len(ff) == 0 {
		return fmt.Errorf("there is no file to print info")
	}

	c := 1
	for _, f := range ff {
		if _, err := kld.Info(f, false); err != nil {
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
