package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

func generateKey(password string) ([]byte, error) {
	hash := sha256.Sum256([]byte(password))
	return hash[:], nil
}

func EncryptFile(file string, password string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	key, err := generateKey(password)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create block: %w", err)
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

	return os.WriteFile(file+".enc", ciphertext, 0644)
}

func DecryptFile(file string, password string) error {
	ciphertext, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	key, err := generateKey(password)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to generate block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("ciphertext too short")
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt file: password is wrong or data tampered.")
	}

	fmt.Println("[!OK], DATA: ", string(plaintext))

	return nil
}
