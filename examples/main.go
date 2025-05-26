package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/MichaelAJay/go-encrypter"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go [encrypt|decrypt|hash-pwd|verify-pwd|encrypt-aad|custom-params]")
		os.Exit(1)
	}

	// Generate or load a key for encryption
	key := generateKey()

	// Create an encrypter with default parameters
	enc, err := encrypter.NewAESEncrypter(key)
	if err != nil {
		log.Fatalf("Failed to create encrypter: %v", err)
	}

	command := os.Args[1]

	switch command {
	case "encrypt":
		demonstrateEncryption(enc)
	case "decrypt":
		demonstrateDecryption(enc)
	case "hash-pwd":
		demonstratePasswordHashing(enc)
	case "verify-pwd":
		demonstratePasswordVerification(enc)
	case "encrypt-aad":
		demonstrateAADEncryption(enc)
	case "custom-params":
		demonstrateCustomParameters(key)
	default:
		fmt.Println("Unknown command")
		os.Exit(1)
	}
}

// generateKey creates a random 32-byte key for AES-256
// In production, this should come from a secure key management system
func generateKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("Failed to generate random key: %v", err)
	}
	return key
}

// demonstrateEncryption shows basic encryption
func demonstrateEncryption(enc *encrypter.AESEncrypter) {
	plaintext := []byte("This is a secret message")
	fmt.Printf("Original plaintext: %s\n", plaintext)

	// Encrypt the data
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	// Display the encrypted data
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	fmt.Printf("Encrypted (Base64): %s\n", encoded)
}

// demonstrateDecryption shows basic decryption
func demonstrateDecryption(enc *encrypter.AESEncrypter) {
	// This should be the output from the encryption example
	encodedCiphertext := "YOUR_BASE64_CIPHERTEXT_HERE"
	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		log.Fatalf("Base64 decoding failed: %v", err)
	}

	// Decrypt the data
	plaintext, err := enc.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	fmt.Printf("Decrypted plaintext: %s\n", plaintext)
}

// demonstratePasswordHashing shows how to hash passwords
func demonstratePasswordHashing(enc *encrypter.AESEncrypter) {
	password := []byte("correct-horse-battery-staple")
	fmt.Printf("Original password: %s\n", password)

	// Hash the password
	hashedPassword, err := enc.HashPassword(password)
	if err != nil {
		log.Fatalf("Password hashing failed: %v", err)
	}

	fmt.Printf("Hashed password: %s\n", hashedPassword)
}

// demonstratePasswordVerification shows how to verify passwords
func demonstratePasswordVerification(enc *encrypter.AESEncrypter) {
	// This should be the output from the password hashing example
	hashedPassword := []byte("YOUR_HASHED_PASSWORD_HERE")

	// Test with correct password
	correctPassword := []byte("correct-horse-battery-staple")
	isValid, err := enc.VerifyPassword(hashedPassword, correctPassword)
	if err != nil {
		log.Fatalf("Password verification failed: %v", err)
	}

	fmt.Printf("Correct password valid: %v\n", isValid)

	// Test with incorrect password
	wrongPassword := []byte("incorrect-horse-battery-staple")
	isValid, err = enc.VerifyPassword(hashedPassword, wrongPassword)
	if err != nil {
		log.Fatalf("Password verification failed: %v", err)
	}

	fmt.Printf("Wrong password valid: %v\n", isValid)
}

// demonstrateAADEncryption shows encryption with additional authenticated data
func demonstrateAADEncryption(enc *encrypter.AESEncrypter) {
	plaintext := []byte("This message is tied to user context")

	// Additional authenticated data - could be user ID, session ID, etc.
	aad := []byte("user_123_session_456")

	fmt.Printf("Original plaintext: %s\n", plaintext)
	fmt.Printf("Context (AAD): %s\n", aad)

	// Encrypt with AAD
	ciphertext, err := enc.EncryptWithAAD(plaintext, aad)
	if err != nil {
		log.Fatalf("Encryption with AAD failed: %v", err)
	}

	// Display the encrypted data
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	fmt.Printf("Encrypted with AAD (Base64): %s\n", encoded)

	// Decrypt with correct AAD
	decrypted, err := enc.DecryptWithAAD(ciphertext, aad)
	if err != nil {
		log.Fatalf("Decryption with AAD failed: %v", err)
	}

	fmt.Printf("Decrypted with correct AAD: %s\n", decrypted)

	// Try decrypting with wrong AAD
	wrongAAD := []byte("user_456_session_123")
	_, err = enc.DecryptWithAAD(ciphertext, wrongAAD)
	if err != nil {
		fmt.Printf("Expected failure with wrong AAD: %v\n", err)
	} else {
		fmt.Println("WARNING: Decryption succeeded with wrong AAD!")
	}
}

// demonstrateCustomParameters shows how to use custom Argon2 parameters
func demonstrateCustomParameters(key []byte) {
	// Define custom parameters for high-security environments
	customParams := encrypter.ArgonParams{
		Memory:     262144, // 256MB
		Iterations: 3,
		Threads:    8,
		SaltLength: 32,
		KeyLength:  32,
	}

	// Create encrypter with custom parameters
	enc, err := encrypter.NewAESEncrypterWithArgonParams(key, customParams)
	if err != nil {
		log.Fatalf("Failed to create encrypter with custom params: %v", err)
	}

	// Hash a password with the custom parameters
	password := []byte("secure-password-123")
	hashedPassword, err := enc.HashPassword(password)
	if err != nil {
		log.Fatalf("Password hashing with custom params failed: %v", err)
	}

	fmt.Printf("Password hashed with custom parameters: %s\n", hashedPassword)

	// Verify the parameters were used
	fmt.Println("Parameters in hash:")
	fmt.Printf("  Memory: %d\n", customParams.Memory)
	fmt.Printf("  Iterations: %d\n", customParams.Iterations)
	fmt.Printf("  Threads: %d\n", customParams.Threads)
}
