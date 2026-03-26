package handlers

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/fatali-fataliyev/kilid/engine"
)

func HandleEncryption(files []string, password string) error {
	n := GetCountOfExistFiles(files)

	switch n {
	case 0:
		return fmt.Errorf("there is no file to encrypt.")
	case 1:
		if err := engine.EncryptFile(files[0], password); err != nil {
			return err
		}
		slog.Info("File encrypted successfully.")
		return nil
	default:
		for _, f := range files {
			engine.EncryptFile(f, password)
		}
	}

	return nil
}

func HandleDecryption(files []string, password string) error {
	n := GetCountOfExistFiles(files)

	switch n {
	case 0:
		return fmt.Errorf("there is no file to encrypt.")
	case 1:
		if err := engine.DecryptFile(files[0], password); err != nil {
			return err
		}
		slog.Info("File decrypted successfully.")
		return nil
	default:
		for _, f := range files {
			engine.DecryptFile(f, password)
		}
	}

	return nil
}

func GetCountOfExistFiles(files []string) int {
	var c int64
	var wg sync.WaitGroup

	for _, f := range files {
		wg.Add(1)

		go func(file string) {
			defer wg.Done()

			info, err := os.Stat(strings.TrimSpace(file))
			if os.IsNotExist(err) {
				slog.Error("file does not exist: ", file)
				return
			}

			if info.IsDir() {
				slog.Error(file, "is a directory, not a file.")
				return
			}

			atomic.AddInt64(&c, 1)
		}(f)
	}

	wg.Wait()
	total := int(atomic.LoadInt64(&c))
	return total
}
