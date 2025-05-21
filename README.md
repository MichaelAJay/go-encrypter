# Go Secure Encrypter

A secure, production-ready Go package that provides encryption, decryption, and password hashing services using modern cryptographic primitives.

## Features

- **AES-GCM Encryption**: Authenticated encryption with associated data (AEAD)
- **Argon2id Password Hashing**: Strong, memory-hard password hashing with tunable parameters
- **HMAC-SHA256**: For secure data lookups and integrity verification
- **Additional Authenticated Data (AAD) Support**: Bind encrypted data to specific contexts
- **Parameter Validation**: Ensures cryptographic operations meet minimum security requirements

## Installation

```bash
go get github.com/yourusername/encrypter
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/yourusername/encrypter"
)

func main() {
    // Create a secure random key
    key := make([]byte, 32) // 32 bytes for AES-256
    
    // In production, use a secure key management solution
    // This is just for example purposes
    _, err := rand.Read(key)
    if err != nil {
        log.Fatal(err)
    }
    
    // Create an encrypter with default parameters
    enc, err := encrypter.NewAESEncrypter(key)
    if err != nil {
        log.Fatal(err)
    }
    
    // Encrypt some data
    plaintext := []byte("sensitive information")
    ciphertext, err := enc.Encrypt(plaintext)
    if err != nil {
        log.Fatal(err)
    }
    
    // Decrypt the data
    decrypted, err := enc.Decrypt(ciphertext)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Decrypted: %s\n", decrypted)
}
```

## Usage

### Encryption with Context (AAD)

```go
// Encrypt with additional authenticated data for context binding
contextID := []byte("user_123_session_456")
ciphertext, err := enc.EncryptWithAAD(plaintext, contextID)

// Decrypt using the same context
decrypted, err := enc.DecryptWithAAD(ciphertext, contextID)
```

### Password Hashing and Verification

```go
// Hash a password
password := []byte("secure-password-123")
hashedPassword, err := enc.HashPassword(password)

// Verify a password against a hash
isValid, err := enc.VerifyPassword(hashedPassword, password)
if isValid {
    fmt.Println("Password is valid")
} else {
    fmt.Println("Password is invalid")
}
```

### Lookup Data Hashing

```go
// Hash data for secure lookups
userEmail := []byte("user@example.com")
hashedEmail := enc.HashLookupData(userEmail)
```

## Security Considerations

### AES Key Size

This package supports AES-128, AES-192, and AES-256:

- 16 bytes (128 bits) - Secure for most applications
- 24 bytes (192 bits) - Higher security margin
- 32 bytes (256 bits) - Maximum security

### Argon2id Parameters

The default parameters are:

- Memory: 128MB
- Iterations: 1 (following Argon2 recommendations)
- Parallelism: 4 threads
- Salt Length: 16 bytes
- Key Length: 32 bytes

You can customize these parameters:

```go
customParams := encrypter.ArgonParams{
    Memory:     262144, // 256MB
    Iterations: 2,
    Threads:    8,
    SaltLength: 16,
    KeyLength:  32,
}

enc, err := encrypter.NewAESEncrypterWithArgonParams(key, customParams)
```

## Best Practices

1. **Key Management**: Securely generate and store encryption keys
2. **AAD Usage**: Use contextual information as AAD to prevent attacks
3. **Error Handling**: Always check for errors and handle them appropriately
4. **Parameter Tuning**: Adjust Argon2id parameters based on your system's capabilities

## License

[MIT License](LICENSE)