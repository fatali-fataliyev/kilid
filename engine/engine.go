package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Kilid struct {
	Version string
}

func NewKilid(v string) *Kilid {
	return &Kilid{
		Version: v,
	}
}

type EncryptedFile struct {
	OriginalExtension string `json:"original_extension"`
	PasswordHint      string `json:"password_hint"`
	EncrpytedData     []byte `json:"encrypted_data"`
	EncryptedAt       string `json:"date"`
	KilidVersion      string `json:"kilid_version"`
}

func generateKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

func (kld *Kilid) EncryptFile(file string, password string, hint string, deleteSource bool, yesAll bool) error {
	var ef EncryptedFile

	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	block, err := aes.NewCipher(generateKey(password))
	if err != nil {
		return fmt.Errorf("failed to generate block from password: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to encrypt file: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	ef.OriginalExtension = filepath.Ext(file)
	ef.PasswordHint = hint
	ef.EncrpytedData = ciphertext
	ef.EncryptedAt = time.Now().Format("2006-01-02 15:04:05")
	ef.KilidVersion = kld.Version

	b, err := json.Marshal(ef)
	if err != nil {
		return fmt.Errorf("failed to convert encrypted file to json: %w", err)
	}

	f := getFileName(file) + ".kld"
	if isFileExistsAlready(f) {
		slog.Warn(fmt.Sprintf("%q already exists, overwrite? [y/n]", f))
		var answer string
		if yesAll {
			answer = "y"
		} else {
			fmt.Scanln(&answer)
			answer = strings.TrimSpace(answer)
			answer = strings.ToLower(answer)
		}

		switch answer {
		case "y":
			return saveFile(b, f)
		case "n":
			return fmt.Errorf("operation aborted")
		default:
			return saveFile(b, f)
		}
	}

	if err := saveFile(b, f); err != nil {
		return err
	}
	if deleteSource {
		if err := deleteSourceFile(file); err != nil {
			return err
		}
	}

	return nil
}

func (kld *Kilid) DecryptFile(file string, password string, deleteSource bool, yesAll bool) (string, error) {
	if filepath.Ext(file) != ".kld" {
		return "", fmt.Errorf("only .kld files can be decrypted")
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	var ef EncryptedFile
	if err := json.Unmarshal(data, &ef); err != nil {
		return "", fmt.Errorf("failed to parse encrypted file to json: %w", err)
	}

	block, err := aes.NewCipher(generateKey(password))
	if err != nil {
		return "", fmt.Errorf("failed to generate block from password: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ef.EncrpytedData) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, actualCiphertext := ef.EncrpytedData[:nonceSize], ef.EncrpytedData[nonceSize:]

	decryptedData, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return ef.PasswordHint, fmt.Errorf("password is wrong or data tampered")
	}

	f := getFileName(file) + ef.OriginalExtension
	if isFileExistsAlready(f) {
		slog.Warn(fmt.Sprintf("%q already exists, overwrite? [y/n]", f))
		var answer string
		if yesAll {
			answer = "y"
		} else {
			fmt.Scanln(&answer)
			answer = strings.TrimSpace(answer)
			answer = strings.ToLower(answer)
		}

		switch answer {
		case "y":
			return "", saveFile(decryptedData, f)
		case "n":
			return "", fmt.Errorf("operation cancelled")
		default:
			return "", saveFile(decryptedData, f)
		}
	}

	if err := saveFile(decryptedData, f); err != nil {
		return "", err
	}
	if deleteSource {
		if err := deleteSourceFile(file); err != nil {
			return "", err
		}
	}

	return "", nil
}

func (kld *Kilid) PrintFileInfo(file string) error {
	if filepath.Ext(file) != ".kld" {
		return fmt.Errorf("only .kld files can be printed")
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var ef EncryptedFile

	if err := json.Unmarshal(data, &ef); err != nil {
		return fmt.Errorf("failed to parse raw data to json: %w", err)
	}
	fmt.Printf("\n─── File Details: %s ───\n", file)
	fmt.Printf("%-20s : %s\n", "Original Extension", ef.OriginalExtension)
	fmt.Printf("%-20s : %s\n", "Password Hint", ef.PasswordHint)
	fmt.Printf("%-20s : %s\n", "Encrypted At", ef.EncryptedAt)
	fmt.Printf("%-20s : %v\n", "Kilid Version", ef.KilidVersion)
	fmt.Println(strings.Repeat("─", 45))
	return nil
}

func getFileName(file string) string {
	fileName := filepath.Base(file)
	return strings.TrimSuffix(fileName, filepath.Ext(fileName))
}

func isFileExistsAlready(fileName string) bool {
	i, err := os.Stat(fileName)
	if err == nil && !i.IsDir() {
		return true
	}
	return false
}

func saveFile(b []byte, fileName string) error {
	if err := os.WriteFile(fileName, b, 0644); err != nil {
		return fmt.Errorf("failed to save file: %w", err)
	}
	return nil
}

func deleteSourceFile(fileName string) error {
	if err := os.Remove(fileName); err != nil {
		return fmt.Errorf("failed to delete source file: %w", err)
	}
	return nil
}
