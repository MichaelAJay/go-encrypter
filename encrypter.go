package encrypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Encrypter provides encryption and decryption services
type Encrypter interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
	HashPassword(password []byte) ([]byte, error)
	VerifyPassword(hashedPassword, password []byte) (bool, error)
	HashLookupData(data []byte) []byte
}

type ArgonParams struct {
	Memory     uint32
	Iterations uint32
	Threads    uint8
	SaltLength uint32
	KeyLength  uint32
}

type AESEncrypter struct {
	gcm         cipher.AEAD
	key         []byte
	argonParams ArgonParams
}

func DefaultArgonParams() ArgonParams {
	return ArgonParams{
		Memory:     65536, // 64MB
		Iterations: 1,     // Following Argon2 recommendation
		Threads:    4,
		SaltLength: 16,
		KeyLength:  32,
	}
}

func NewAESEncrypter(key []byte) (*AESEncrypter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AESEncrypter{
		gcm:         gcm,
		key:         key,
		argonParams: DefaultArgonParams(),
	}, nil
}

func NewAESEncrypterWithArgonParams(key []byte, argonParams ArgonParams) (*AESEncrypter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AESEncrypter{
		gcm:         gcm,
		key:         key,
		argonParams: argonParams,
	}, nil
}

// Encrypt encrypts plaintext using AES-GCM
func (e *AESEncrypter) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and append nonce
	ciphertext := e.gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-GCM
func (e *AESEncrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := e.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// HashPassword hashes a password using Argon2id with random salt
func (e *AESEncrypter) HashPassword(password []byte) ([]byte, error) {
	salt := make([]byte, e.argonParams.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	hash := argon2.IDKey(
		password,
		salt,
		e.argonParams.Iterations,
		e.argonParams.Memory,
		e.argonParams.Threads,
		e.argonParams.KeyLength,
	)

	// Format: $argon2id$v=19$m=65536,t=1,p=4$salt$hash
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		e.argonParams.Memory,
		e.argonParams.Iterations,
		e.argonParams.Threads,
		b64Salt,
		b64Hash,
	)

	return []byte(encodedHash), nil
}

// VerifyPassword verifies a password against a hashed password
func (e *AESEncrypter) VerifyPassword(hashedPassword, password []byte) (bool, error) {
	parts := strings.Split(string(hashedPassword), "$")
	if len(parts) != 6 {
		return false, errors.New("invalid hashed password format")
	}

	version := parts[1]
	if version != "19" {
		return false, errors.New("unsupported argon2 version")
	}

	memory, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return false, errors.New("invalid memory parameter")
	}

	iterations, err := strconv.ParseUint(parts[3], 10, 32)
	if err != nil {
		return false, errors.New("invalid iterations parameter")
	}

	threads, err := strconv.ParseUint(parts[4], 10, 8)
	if err != nil {
		return false, errors.New("invalid threads parameter")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("invalid salt")
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[6])
	if err != nil {
		return false, errors.New("invalid hash")
	}

	computedHash := argon2.IDKey(password, salt, uint32(iterations), uint32(memory), uint8(threads), uint32(len(decodedHash)))

	return subtle.ConstantTimeCompare(decodedHash, computedHash) == 1, nil
}

// HashLookupData hashes lookup data using SHA-256
func (e *AESEncrypter) HashLookupData(data []byte) []byte {
	h := hmac.New(sha256.New, e.key)
	h.Write(data)
	return h.Sum(nil)
}
