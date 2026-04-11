package engine

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
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
	EncryptedAt       string `json:"date"`
	KilidVersion      string `json:"kilid_version"`
}

func generateKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
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

	md.OriginalExtension = filepath.Ext(file)
	md.PasswordHint = hint
	md.EncryptedAt = time.Now().Format("2006-01-02 15:04:05")
	md.KilidVersion = kld.Version

	b, err := json.Marshal(md)
	if err != nil {
		return fmt.Errorf("failed to create metadata: %w", err)
	}
	n, err := dst.Write(b)
	if err != nil || n != len(b) {
		return fmt.Errorf("failed to write metadata: %w", err)
	}
	n, err = dst.Write([]byte("/"))
	if err != nil || n != 1 {
		return fmt.Errorf("failed to write metadata seperator: %w", err)
	}

	block, err := aes.NewCipher(generateKey(password))
	if err != nil {
		return fmt.Errorf("failed to generate block from password: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to generate GCM: %w", err)
	}

	buf := make([]byte, ChunkSize)

	myBuf := make([]byte, ChunkSize)
	dst.Read(myBuf)

	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			nonce := make([]byte, gcm.NonceSize())
			io.ReadFull(rand.Reader, nonce)

			ciphertext := gcm.Seal(nil, nonce, chunk, nil)
			l := uint32(len(ciphertext))
			binary.Write(dst, binary.LittleEndian, l)

			n, err := dst.Write(nonce)
			if err != nil || n != len(nonce) {
				return fmt.Errorf("failed to save nonce: %w", err)
			}
			n, err = dst.Write(ciphertext)
			if err != nil || n != len(ciphertext) {
				return fmt.Errorf("failed to save chunk: %w", err)
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

func (kld *Kilid) DecryptFile(file string, password string, deleteSource bool, yesAll bool, onProgress func(int)) []error {
	if filepath.Ext(file) != ".kld" {
		return []error{fmt.Errorf("only .kld files can be decrypted")}
	}

	src, err := os.Open(file)
	if err != nil {
		return []error{fmt.Errorf("failed to open file: %w", err)}
	}
	defer src.Close()

	var md MetaData
	r := bufio.NewReader(src)
	metadataBytes, err := r.ReadBytes('/')
	if err != nil {
		return []error{fmt.Errorf("failed to read metadata: %w", err)}
	}
	onProgress(len(metadataBytes))
	metadataStr := string(metadataBytes)
	metadataStr = strings.TrimSuffix(metadataStr, "/")

	if err := json.Unmarshal([]byte(metadataStr), &md); err != nil {
		return []error{fmt.Errorf("failed to parse metadata: %w", err)}
	}

	dst, err := os.Create(kld.GetFileName(file) + md.OriginalExtension)
	if err != nil {
		return []error{fmt.Errorf("failed to create output file: %w", err)}
	}
	defer dst.Close()

	block, err := aes.NewCipher(generateKey(password))
	if err != nil {
		return []error{fmt.Errorf("failed to generate block from password: %w", err)}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []error{fmt.Errorf("failed to create GCM: %w", err)}
	}

	nonceSize := gcm.NonceSize()

	for {
		var length uint32
		err := binary.Read(r, binary.LittleEndian, &length)
		if err == io.EOF {
			break
		}
		if err != nil {
			return []error{fmt.Errorf("failed to read chunk length: %w", err)}
		}

		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(r, nonce); err != nil {
			return []error{fmt.Errorf("failed to read nonce: %w", err)}
		}

		ciphertext := make([]byte, length)
		if _, err := io.ReadFull(r, ciphertext); err != nil {
			return []error{fmt.Errorf("failed to read ciphertext: %w", err)}
		}

		plaindata, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			dst.Close()
			if err := os.Remove(dst.Name()); err != nil {
				return []error{fmt.Errorf("failed to delete temoporary output file: %w", err), fmt.Errorf("password is wrong or data tampered"), fmt.Errorf("Password Hint: %s", md.PasswordHint)}
			}
			return []error{fmt.Errorf("password is wrong or data tampered"), fmt.Errorf("Password Hint: %s", md.PasswordHint)}
		}

		if _, err := dst.Write(plaindata); err != nil {
			return []error{fmt.Errorf("failed to save data: %w", err)}
		}

		bytesConsumed := 4 + nonceSize + int(length) // I forget to calc overheeads caused: Progress bar deadlock.
		onProgress(bytesConsumed)
	}

	if deleteSource {
		if err := deleteSourceFile(file); err != nil {
			return []error{err}
		}
	}

	return nil

}

func (kld *Kilid) Info(file string, onlyExt bool) (string, error) {
	if filepath.Ext(file) != ".kld" {
		return "", fmt.Errorf("only .kld files can be printed")
	}

	src, err := os.Open(file)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	r := bufio.NewReader(src)
	b, err := r.ReadBytes('/')
	if err != nil {
		return "", fmt.Errorf("failed to read metadata: %w", err)
	}
	src.Close()
	mdString := string(b)
	mdString = strings.TrimSuffix(mdString, "/")

	var md MetaData

	if err := json.Unmarshal([]byte(mdString), &md); err != nil {
		return "", fmt.Errorf("failed to parse metadata: %w", err)
	}

	if onlyExt {
		return md.OriginalExtension, nil
	}

	fmt.Printf("\n─── File Details: %s ───\n", file)
	fmt.Printf("%-20s : %s\n", "Original Extension", md.OriginalExtension)
	fmt.Printf("%-20s : %s\n", "Password Hint", md.PasswordHint)
	fmt.Printf("%-20s : %s\n", "Encrypted At", md.EncryptedAt)
	fmt.Printf("%-20s : %v\n", "Kilid Version", md.KilidVersion)
	fmt.Println(strings.Repeat("─", 45))
	return "", nil
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
