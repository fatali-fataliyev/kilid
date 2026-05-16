package engine

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

type Kilid struct {
	Version string
}

const ChunkSize = 1024 * 1024 // 1MB

func NewKilid(v string) *Kilid {
	return &Kilid{
		Version: v,
	}
}

type MetaData struct {
	OriginalExtension string `json:"ext"`
	PasswordHint      string `json:"hint"`
	Date              string `json:"date"`
	Version           string `json:"version"`
	Salt              string `json:"salt"`
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 4, 256*1024, 4, 32)
}

func (kld *Kilid) EncryptFile(file string, password string, hint string, deleteSource bool, yesAll bool, onProgress func(int)) error {
	var md MetaData

	src, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(kld.GetFileName(file) + ".kld")
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer dst.Close()

	salt, err := generateSalt()
	if err != nil {
		return err
	}

	md.OriginalExtension = filepath.Ext(file)
	md.PasswordHint = hint
	md.Date = time.Now().Format("2006-01-02 15:04:05")
	md.Version = kld.Version
	md.Salt = hex.EncodeToString(salt)

	b, err := json.Marshal(md)
	if err != nil {
		return fmt.Errorf("failed to create metadata: %w", err)
	}
	if _, err := dst.Write(b); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}
	if _, err = dst.Write([]byte("/")); err != nil {
		return fmt.Errorf("failed to write metadata delimiter: %w", err)
	}

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM counter: %w", err)
	}

	buf := make([]byte, ChunkSize)

	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			nonce := make([]byte, gcm.NonceSize())
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				return fmt.Errorf("failed to generate nonce: %w", err)
			}

			ciphertext := gcm.Seal(nil, nonce, chunk, nil)
			if err := binary.Write(dst, binary.LittleEndian, uint32(len(ciphertext))); err != nil {
				return err
			}

			if _, err := dst.Write(nonce); err != nil {
				return fmt.Errorf("failed to save nonce: %w", err)
			}
			if _, err = dst.Write(ciphertext); err != nil {
				return fmt.Errorf("failed to save ciphertext: %w", err)
			}

			onProgress(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read chunk: %w", err)
		}
	}

	if deleteSource {
		if err := deleteSourceFile(file); err != nil {
			return err
		}
	}

	return nil
}

func (kld *Kilid) DecryptFile(file string, password string, deleteSource bool, yesAll bool, onProgress func(int)) error {
	if filepath.Ext(file) != ".kld" {
		return fmt.Errorf("only .kld files can be decrypted")
	}

	src, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer src.Close()

	var md MetaData
	r := bufio.NewReader(src)
	b, err := r.ReadBytes('/')
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}
	onProgress(len(b))
	metadataStr := string(b)
	metadataStr = strings.TrimSuffix(metadataStr, "/")

	if err := json.Unmarshal([]byte(metadataStr), &md); err != nil {
		return fmt.Errorf("failed to parse metadata: %w", err)
	}

	dst, err := os.Create(kld.GetFileName(file) + md.OriginalExtension)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer dst.Close()

	salt, err := hex.DecodeString(md.Salt)
	if err != nil {
		return fmt.Errorf("failed to convert salt: %w", err)
	}

	block, err := aes.NewCipher(deriveKey(password, salt))
	if err != nil {
		return fmt.Errorf("failed to create block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM counter: %w", err)
	}

	nonceSize := gcm.NonceSize()

	for {
		var length uint32
		err := binary.Read(r, binary.LittleEndian, &length)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read length: %w", err)
		}

		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(r, nonce); err != nil {
			return fmt.Errorf("failed to read nonce: %w", err)
		}

		ciphertext := make([]byte, length)
		if _, err := io.ReadFull(r, ciphertext); err != nil {
			return fmt.Errorf("failed to read ciphertext: %w", err)
		}

		plaindata, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			dst.Close()
			return fmt.Errorf("password is wrong or data tampered | Password Hint: %q", md.PasswordHint)
		}

		if _, err := dst.Write(plaindata); err != nil {
			return fmt.Errorf("failed to save data: %w", err)
		}

		bytesConsumed := 4 + nonceSize + int(length)
		onProgress(bytesConsumed)
	}

	if deleteSource {
		if err := deleteSourceFile(file); err != nil {
			return err
		}
	}

	return nil
}

func (kld *Kilid) WipeFile(file string, onProgress func(int)) error {
	src, err := os.OpenFile(file, os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer src.Close()

	stats, err := src.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file statistics: %w", err)
	}
	fileSize := stats.Size()

	buf := make([]byte, ChunkSize)
	var totalProcessed int64

	for totalProcessed < fileSize {
		n, err := src.Read(buf)
		if n > 0 {
			scrambledData := make([]byte, n)
			if _, err = rand.Read(scrambledData); err != nil {
				return fmt.Errorf("failed to fill scramble data: %w", err)
			}

			if _, err = src.Seek(int64(-n), io.SeekCurrent); err != nil {
				return fmt.Errorf("failed to seek file cursor: %w", err)
			}

			if _, err = src.Write(scrambledData); err != nil {
				return fmt.Errorf("failed to write scrabled data: %w", err)
			}

			totalProcessed += int64(n)
			onProgress(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
	}
	if err := os.Remove(file); err != nil {
		return fmt.Errorf("failed to remove file after wiping: %w", err)
	}
	return nil
}

func (kld *Kilid) Info(file string) (MetaData, error) {
	md, err := getMetadata(file)
	if err != nil {
		return MetaData{}, fmt.Errorf("failed to get metadata: %w", err)
	}

	return md, nil
}

func (kld *Kilid) GetFileRealExt(file string) (string, error) {
	md, err := getMetadata(file)
	if err != nil {
		return "", fmt.Errorf("failed to get file extension: %w", err)
	}

	return md.OriginalExtension, nil
}

func getMetadata(file string) (MetaData, error) {
	if filepath.Ext(file) != ".kld" {
		return MetaData{}, fmt.Errorf("only .kld files can be printed")
	}

	src, err := os.Open(file)
	if err != nil {
		return MetaData{}, fmt.Errorf("failed to open file: %w", err)
	}
	r := bufio.NewReader(src)
	b, err := r.ReadBytes('/')
	if err != nil {
		return MetaData{}, fmt.Errorf("failed to read metadata: %w", err)
	}
	src.Close()
	mdString := string(b)
	mdString = strings.TrimSuffix(mdString, "/")

	var md MetaData

	if err := json.Unmarshal([]byte(mdString), &md); err != nil {
		return MetaData{}, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return md, nil
}

func (kld *Kilid) GetFileName(file string) string {
	fileName := filepath.Base(file)
	return strings.TrimSuffix(fileName, filepath.Ext(fileName))
}

func deleteSourceFile(fileName string) error {
	if err := os.Remove(fileName); err != nil {
		return fmt.Errorf("failed to delete source file: %w", err)
	}
	return nil
}
