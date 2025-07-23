package encrypter

import (
	"errors"
	"sync"

	"github.com/MichaelAJay/go-logger"
)

// KeyManager manages multiple encryption keys for seamless key rotation
// Production Best Practice: This enables zero-downtime key rotation and gradual migration
type KeyManager struct {
	logger     logger.Logger
	keys       map[string]*AESEncrypter // version -> encrypter
	currentKey string                   // current key version for new encryptions
	mu         sync.RWMutex             // protects concurrent access
}

// NewKeyManager creates a new key manager with an initial key
func NewKeyManager(initialEncrypter *AESEncrypter, log logger.Logger) *KeyManager {
	km := &KeyManager{
		logger:     log,
		keys:       make(map[string]*AESEncrypter),
		currentKey: initialEncrypter.GetKeyVersion(),
	}

	// Set logger on the encrypter if not already set
	if log != nil && !initialEncrypter.HasLogger() {
		initialEncrypter.SetLogger(log)
	}

	km.keys[initialEncrypter.GetKeyVersion()] = initialEncrypter

	if log != nil {
		log.Info("Key manager initialized",
			logger.Field{Key: "initial_version", Value: initialEncrypter.GetKeyVersion()},
		)
	}

	return km
}

// AddKey adds a new key version to the manager
func (km *KeyManager) AddKey(encrypter *AESEncrypter) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	version := encrypter.GetKeyVersion()
	if _, exists := km.keys[version]; exists {
		return errors.New("key version already exists: " + version)
	}

	// Set logger on the new encrypter if not already set
	if km.logger != nil && !encrypter.HasLogger() {
		encrypter.SetLogger(km.logger)
	}

	km.keys[version] = encrypter

	if km.logger != nil {
		km.logger.Info("New key version added",
			logger.Field{Key: "version", Value: version},
			logger.Field{Key: "total_keys", Value: len(km.keys)},
		)
	}

	return nil
}

// SetCurrentKey sets the key version to use for new encryptions
func (km *KeyManager) SetCurrentKey(version string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if _, exists := km.keys[version]; !exists {
		return errors.New("key version not found: " + version)
	}

	oldVersion := km.currentKey
	km.currentKey = version

	if km.logger != nil {
		km.logger.Info("Current key version changed",
			logger.Field{Key: "old_version", Value: oldVersion},
			logger.Field{Key: "new_version", Value: version},
		)
	}

	return nil
}

// Encrypt encrypts data using the current key version
func (km *KeyManager) Encrypt(data []byte) ([]byte, error) {
	km.mu.RLock()
	encrypter := km.keys[km.currentKey]
	version := km.currentKey
	km.mu.RUnlock()

	if encrypter == nil {
		return nil, errors.New("no current key available")
	}

	ciphertext, err := encrypter.Encrypt(data)
	if err != nil {
		if km.logger != nil {
			km.logger.Error("Encryption failed",
				logger.Field{Key: "key_version", Value: version},
				logger.Field{Key: "error", Value: err.Error()},
			)
		}
		return nil, err
	}

	// Prepend version info to ciphertext for decryption routing
	return prependVersion(version, ciphertext), nil
}

// Decrypt decrypts data using the appropriate key version
func (km *KeyManager) Decrypt(data []byte) ([]byte, error) {
	// Extract version from data
	version, ciphertext, err := extractVersion(data)
	if err != nil {
		// Fallback: try current key for backward compatibility
		km.mu.RLock()
		encrypter := km.keys[km.currentKey]
		currentVersion := km.currentKey
		km.mu.RUnlock()

		if encrypter == nil {
			return nil, errors.New("no key available for decryption")
		}

		result, decryptErr := encrypter.Decrypt(data)
		if decryptErr != nil && km.logger != nil {
			km.logger.Warn("Decryption failed with current key (legacy data?)",
				logger.Field{Key: "key_version", Value: currentVersion},
				logger.Field{Key: "version_error", Value: err.Error()},
				logger.Field{Key: "decrypt_error", Value: decryptErr.Error()},
			)
		}
		return result, decryptErr
	}

	km.mu.RLock()
	encrypter := km.keys[version]
	km.mu.RUnlock()

	if encrypter == nil {
		if km.logger != nil {
			km.logger.Error("Key version not found for decryption",
				logger.Field{Key: "requested_version", Value: version},
				logger.Field{Key: "available_versions", Value: km.getVersionList()},
			)
		}
		return nil, errors.New("key version not found: " + version)
	}

	return encrypter.Decrypt(ciphertext)
}

// RemoveKey removes an old key version (use after migration is complete)
func (km *KeyManager) RemoveKey(version string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if version == km.currentKey {
		return errors.New("cannot remove current key version")
	}

	if _, exists := km.keys[version]; !exists {
		return errors.New("key version not found: " + version)
	}

	delete(km.keys, version)

	if km.logger != nil {
		km.logger.Info("Key version removed",
			logger.Field{Key: "version", Value: version},
			logger.Field{Key: "remaining_keys", Value: len(km.keys)},
		)
	}

	return nil
}

// GetVersions returns all available key versions
func (km *KeyManager) GetVersions() []string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.getVersionList()
}

// GetCurrentVersion returns the current key version
func (km *KeyManager) GetCurrentVersion() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.currentKey
}

// GetKeyMetadata returns metadata for all keys
func (km *KeyManager) GetKeyMetadata() map[string]map[string]any {
	km.mu.RLock()
	defer km.mu.RUnlock()

	metadata := make(map[string]map[string]any)
	for version, encrypter := range km.keys {
		metadata[version] = encrypter.GetKeyMetadata()
		metadata[version]["is_current"] = version == km.currentKey
	}

	return metadata
}

// Helper methods
func (km *KeyManager) getVersionList() []string {
	versions := make([]string, 0, len(km.keys))
	for version := range km.keys {
		versions = append(versions, version)
	}
	return versions
}

// Version encoding/decoding for data format
// Format: [1 byte version length][version string][ciphertext]
func prependVersion(version string, data []byte) []byte {
	versionBytes := []byte(version)
	result := make([]byte, 1+len(versionBytes)+len(data))
	result[0] = byte(len(versionBytes))
	copy(result[1:], versionBytes)
	copy(result[1+len(versionBytes):], data)
	return result
}

func extractVersion(data []byte) (string, []byte, error) {
	if len(data) < 1 {
		return "", nil, errors.New("data too short to contain version")
	}

	versionLen := int(data[0])
	if len(data) < 1+versionLen {
		return "", nil, errors.New("data too short to contain version string")
	}

	version := string(data[1 : 1+versionLen])
	ciphertext := data[1+versionLen:]

	return version, ciphertext, nil
}
