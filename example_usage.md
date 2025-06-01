# Production Key Management Examples

## Basic Usage with Key Versioning

```go
package main

import (
    "github.com/MichaelAJay/go-encrypter"
    "github.com/MichaelAJay/go-logger"
)

func main() {
    // Create logger
    log := logger.New(logger.DefaultConfig)
    
    // Create encrypter with version and logger in one step (recommended)
    key := []byte("32-byte-key-for-aes-256-encryption!")
    enc, err := encrypter.NewAESEncrypterWithLogger(key, "v1.0", log)
    if err != nil {
        panic(err)
    }
    
    // Encrypt some data
    plaintext := []byte("sensitive user data")
    ciphertext, err := enc.Encrypt(plaintext)
    if err != nil {
        panic(err)
    }
    
    // Decrypt data
    decrypted, err := enc.Decrypt(ciphertext)
    if err != nil {
        panic(err)
    }
    
    log.Info("Encryption test successful",
        logger.Field{Key: "key_version", Value: enc.GetKeyVersion()},
    )
}
```

## Production Key Rotation with KeyManager

```go
package main

import (
    "time"
    "github.com/MichaelAJay/go-encrypter"
    "github.com/MichaelAJay/go-logger"
)

func main() {
    // Setup logging
    log := logger.New(logger.DefaultConfig)
    
    // Create initial encrypter with logger (cleaner one-step initialization)
    oldKey := []byte("old-32-byte-key-for-aes-256-enc!")
    oldEnc, _ := encrypter.NewAESEncrypterWithLogger(oldKey, "v1.0", log)
    
    // Create key manager
    km := encrypter.NewKeyManager(oldEnc, log)
    
    // Encrypt some data with v1.0
    userData := []byte("important user data")
    encrypted, err := km.Encrypt(userData)
    if err != nil {
        panic(err)
    }
    
    // Time for key rotation...
    newKey := []byte("new-32-byte-key-for-aes-256-enc!")
    newEnc, _ := encrypter.NewAESEncrypterWithLogger(newKey, "v2.0", log)
    
    // Add new key (logger is already set)
    err = km.AddKey(newEnc)
    if err != nil {
        panic(err)
    }
    
    // Switch to new key for new encryptions
    err = km.SetCurrentKey("v2.0")
    if err != nil {
        panic(err)
    }
    
    // New data uses v2.0, old data still decrypts with v1.0
    newData, _ := km.Encrypt([]byte("new data"))
    
    // Both old and new data can be decrypted
    oldDecrypted, _ := km.Decrypt(encrypted)  // Uses v1.0
    newDecrypted, _ := km.Decrypt(newData)    // Uses v2.0
    
    log.Info("Key rotation successful",
        logger.Field{Key: "current_version", Value: km.GetCurrentVersion()},
        logger.Field{Key: "available_versions", Value: km.GetVersions()},
    )
}
```

## Integration with User Management Service

```go
// In your user service
type UserService struct {
    keyManager *encrypter.KeyManager
    logger     logger.Logger
}

func (s *UserService) EncryptUserData(data []byte) ([]byte, error) {
    encrypted, err := s.keyManager.Encrypt(data)
    if err != nil {
        s.logger.Error("Failed to encrypt user data",
            logger.Field{Key: "error", Value: err.Error()},
            logger.Field{Key: "key_version", Value: s.keyManager.GetCurrentVersion()},
        )
        return nil, err
    }
    
    s.logger.Debug("User data encrypted",
        logger.Field{Key: "key_version", Value: s.keyManager.GetCurrentVersion()},
        logger.Field{Key: "data_length", Value: len(data)},
    )
    
    return encrypted, nil
}

func (s *UserService) DecryptUserData(data []byte) ([]byte, error) {
    decrypted, err := s.keyManager.Decrypt(data)
    if err != nil {
        s.logger.Error("Failed to decrypt user data",
            logger.Field{Key: "error", Value: err.Error()},
        )
        return nil, err
    }
    
    return decrypted, nil
}

// Scheduled key rotation
func (s *UserService) RotateKeys() error {
    // Generate new key (in production, use HSM or key management service)
    newKey := generateSecureKey() // Your key generation logic
    newVersion := fmt.Sprintf("v%d", time.Now().Unix())
    
    newEnc, err := encrypter.NewAESEncrypterWithVersion(newKey, newVersion)
    if err != nil {
        return err
    }
    
    // Add new key
    err = s.keyManager.AddKey(newEnc)
    if err != nil {
        return err
    }
    
    // Switch to new key
    err = s.keyManager.SetCurrentKey(newVersion)
    if err != nil {
        return err
    }
    
    s.logger.Info("Key rotation completed",
        logger.Field{Key: "new_version", Value: newVersion},
    )
    
    return nil
}
```

## Production Best Practices

### 1. Key Version Naming
```go
// Use semantic versioning or timestamps
"v1.0", "v1.1", "v2.0"           // Semantic
"2024-01-15", "2024-02-15"       // Date-based
"key-001", "key-002"             // Sequential
```

### 2. Monitoring and Alerting
```go
// Monitor key usage
metadata := km.GetKeyMetadata()
for version, meta := range metadata {
    if meta["is_current"].(bool) {
        // Monitor current key usage
        log.Info("Current key stats", 
            logger.Field{Key: "version", Value: version},
            logger.Field{Key: "algorithm", Value: meta["algorithm"]},
        )
    }
}
```

### 3. Gradual Migration
```go
// Implement background job to re-encrypt old data
func (s *UserService) MigrateUserData(userID string) error {
    user, err := s.GetUser(userID)
    if err != nil {
        return err
    }
    
    // Decrypt with old key, re-encrypt with new key
    decrypted, err := s.keyManager.Decrypt(user.EncryptedData)
    if err != nil {
        return err
    }
    
    reencrypted, err := s.keyManager.Encrypt(decrypted)
    if err != nil {
        return err
    }
    
    // Update database
    return s.UpdateUserEncryptedData(userID, reencrypted)
}
```

## Security Considerations

1. **Key Storage**: Never hardcode keys. Use environment variables, HSM, or key management services
2. **Key Rotation Schedule**: Rotate keys regularly (quarterly/yearly)
3. **Audit Trail**: Log all key operations for compliance
4. **Access Control**: Restrict key management operations to authorized personnel
5. **Backup Strategy**: Ensure old keys are securely backed up until migration is complete 