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
	"time"

	"github.com/MichaelAJay/go-logger"
	"golang.org/x/crypto/argon2"
)

// Encrypter provides encryption and decryption services
type Encrypter interface {
	Encrypt(data []byte) ([]byte, error)
	EncryptWithAAD(data, additionalData []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
	DecryptWithAAD(data, additionalData []byte) ([]byte, error)
	HashPassword(password []byte) ([]byte, error)
	VerifyPassword(hashedPassword, password []byte) (bool, error)
	HashLookupData(data []byte) []byte
	GetKeyVersion() string
}

type ArgonParams struct {
	Memory     uint32
	Iterations uint32
	Threads    uint8
	SaltLength uint32
	KeyLength  uint32
}

type AESEncrypter struct {
	logger      logger.Logger
	gcm         cipher.AEAD
	key         []byte
	keyVersion  string
	argonParams ArgonParams
}

func DefaultArgonParams() ArgonParams {
	return ArgonParams{
		Memory:     131072, // 128MB
		Iterations: 1,      // Following Argon2 recommendation
		Threads:    4,
		SaltLength: 16,
		KeyLength:  32,
	}
}

// ValidateArgonParams checks if Argon2 parameters meet minimum security requirements
func ValidateArgonParams(params ArgonParams) error {
	if params.Memory < 32768 {
		return errors.New("memory parameter too low, minimum 32MB (32768) recommended")
	}
	if params.Iterations < 1 {
		return errors.New("iterations parameter must be at least 1")
	}
	if params.Threads < 1 {
		return errors.New("threads parameter must be at least 1")
	}
	if params.SaltLength < 16 {
		return errors.New("salt length must be at least 16 bytes")
	}
	if params.KeyLength < 16 {
		return errors.New("key length must be at least 16 bytes")
	}
	return nil
}

func NewAESEncrypter(key []byte) (*AESEncrypter, error) {
	return NewAESEncrypterWithVersion(key, "v1")
}

func NewAESEncrypterWithVersion(key []byte, keyVersion string) (*AESEncrypter, error) {
	return NewAESEncrypterWithArgonParamsAndVersion(key, DefaultArgonParams(), keyVersion)
}

func NewAESEncrypterWithArgonParams(key []byte, argonParams ArgonParams) (*AESEncrypter, error) {
	return NewAESEncrypterWithArgonParamsAndVersion(key, argonParams, "v1")
}

func NewAESEncrypterWithLogger(key []byte, keyVersion string, log logger.Logger) (*AESEncrypter, error) {
	return NewAESEncrypterComplete(key, DefaultArgonParams(), keyVersion, log)
}

// NewAESEncrypterWithArgonParamsAndVersion creates a new AES encrypter with full configuration
// Production Best Practice: Always specify key version for operational visibility and key rotation
func NewAESEncrypterWithArgonParamsAndVersion(key []byte, argonParams ArgonParams, keyVersion string) (*AESEncrypter, error) {
	return NewAESEncrypterComplete(key, argonParams, keyVersion, nil)
}

// NewAESEncrypterComplete creates a new AES encrypter with all configuration options
// This is the most complete constructor - all others delegate to this one
func NewAESEncrypterComplete(key []byte, argonParams ArgonParams, keyVersion string, log logger.Logger) (*AESEncrypter, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256")
	}

	if keyVersion == "" {
		return nil, errors.New("key version cannot be empty")
	}

	if err := ValidateArgonParams(argonParams); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AESEncrypter{
		logger:      log,
		gcm:         gcm,
		key:         key,
		keyVersion:  keyVersion,
		argonParams: argonParams,
	}, nil
}

// Encrypt encrypts plaintext using AES-GCM without additional data
func (e *AESEncrypter) Encrypt(plaintext []byte) ([]byte, error) {
	return e.EncryptWithAAD(plaintext, nil)
}

// EncryptWithAAD encrypts plaintext using AES-GCM with additional authenticated data
func (e *AESEncrypter) EncryptWithAAD(plaintext, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and append nonce
	ciphertext := e.gcm.Seal(nonce, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-GCM without additional data
func (e *AESEncrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		if e.logger != nil {
			e.logger.Debug("Decrypt operation completed",
				logger.Field{Key: "duration", Value: time.Since(start)},
				logger.Field{Key: "key_version", Value: e.keyVersion},
			)
		}
	}()

	result, err := e.DecryptWithAAD(ciphertext, nil)
	if err != nil && e.logger != nil {
		e.logger.Error("Decryption failed at crypto layer",
			logger.Field{Key: "data_length", Value: len(ciphertext)},
			logger.Field{Key: "key_version", Value: e.keyVersion},
			logger.Field{Key: "duration_ms", Value: time.Since(start).Milliseconds()},
			logger.Field{Key: "error", Value: err.Error()},
		)
	}

	return result, err
}

// DecryptWithAAD decrypts ciphertext using AES-GCM with additional authenticated data
func (e *AESEncrypter) DecryptWithAAD(ciphertext, additionalData []byte) ([]byte, error) {
	nonceSize := e.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, additionalData)
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

	// Format: $argon2id$v=19$m={memory},t={iterations},p={threads}${base64salt}${base64hash}
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

	if parts[1] != "argon2id" {
		return false, errors.New("unsupported hash algorithm")
	}

	var version string
	if !strings.HasPrefix(parts[2], "v=") {
		return false, errors.New("invalid version format")
	}
	version = strings.TrimPrefix(parts[2], "v=")
	if version != "19" {
		return false, errors.New("unsupported argon2 version")
	}

	// Parse parameters
	if !strings.HasPrefix(parts[3], "m=") {
		return false, errors.New("invalid parameters format")
	}

	paramsStr := strings.TrimPrefix(parts[3], "m=")
	paramsParts := strings.Split(paramsStr, ",")
	if len(paramsParts) != 3 {
		return false, errors.New("invalid parameters count")
	}

	// Parse memory
	memoryStr := paramsParts[0]
	memory, err := strconv.ParseUint(memoryStr, 10, 32)
	if err != nil {
		return false, errors.New("invalid memory parameter")
	}

	// Parse iterations
	if !strings.HasPrefix(paramsParts[1], "t=") {
		return false, errors.New("invalid iterations format")
	}
	iterationsStr := strings.TrimPrefix(paramsParts[1], "t=")
	iterations, err := strconv.ParseUint(iterationsStr, 10, 32)
	if err != nil {
		return false, errors.New("invalid iterations parameter")
	}

	// Parse threads
	if !strings.HasPrefix(paramsParts[2], "p=") {
		return false, errors.New("invalid threads format")
	}
	threadsStr := strings.TrimPrefix(paramsParts[2], "p=")
	threads, err := strconv.ParseUint(threadsStr, 10, 8)
	if err != nil {
		return false, errors.New("invalid threads parameter")
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errors.New("invalid salt encoding")
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("invalid hash encoding")
	}

	// Compute hash with the same parameters
	computedHash := argon2.IDKey(
		password,
		salt,
		uint32(iterations),
		uint32(memory),
		uint8(threads),
		uint32(len(decodedHash)),
	)

	// Compare hashes in constant time to prevent timing attacks
	return subtle.ConstantTimeCompare(decodedHash, computedHash) == 1, nil
}

// HashLookupData hashes lookup data using SHA-256
func (e *AESEncrypter) HashLookupData(data []byte) []byte {
	h := hmac.New(sha256.New, e.key)
	h.Write(data)
	return h.Sum(nil)
}

// SetLogger sets the logger for the encrypter
// Production Best Practice: Always set a logger for encryption operations monitoring
func (e *AESEncrypter) SetLogger(logger logger.Logger) {
	e.logger = logger
}

// HasLogger returns true if a logger is already set
func (e *AESEncrypter) HasLogger() bool {
	return e.logger != nil
}

// GetKeyVersion returns the current key version
// This enables key rotation tracking and audit compliance
func (e *AESEncrypter) GetKeyVersion() string {
	return e.keyVersion
}

// RotateKey performs key rotation by creating a new encrypter with a new key and version
// Production Best Practice: This enables zero-downtime key rotation
func (e *AESEncrypter) RotateKey(newKey []byte, newVersion string) (*AESEncrypter, error) {
	if e.logger != nil {
		e.logger.Info("Initiating key rotation",
			logger.Field{Key: "old_version", Value: e.keyVersion},
			logger.Field{Key: "new_version", Value: newVersion},
		)
	}

	// Use the complete constructor to include the current logger
	newEncrypter, err := NewAESEncrypterComplete(newKey, e.argonParams, newVersion, e.logger)
	if err != nil {
		if e.logger != nil {
			e.logger.Error("Key rotation failed",
				logger.Field{Key: "old_version", Value: e.keyVersion},
				logger.Field{Key: "new_version", Value: newVersion},
				logger.Field{Key: "error", Value: err.Error()},
			)
		}
		return nil, err
	}

	if e.logger != nil {
		e.logger.Info("Key rotation completed successfully",
			logger.Field{Key: "old_version", Value: e.keyVersion},
			logger.Field{Key: "new_version", Value: newVersion},
		)
	}

	return newEncrypter, nil
}

// GetKeyMetadata returns metadata about the current key for monitoring and audit
func (e *AESEncrypter) GetKeyMetadata() map[string]interface{} {
	return map[string]interface{}{
		"version":          e.keyVersion,
		"key_length":       len(e.key),
		"algorithm":        "AES-GCM",
		"argon_memory":     e.argonParams.Memory,
		"argon_iterations": e.argonParams.Iterations,
		"argon_threads":    e.argonParams.Threads,
	}
}
