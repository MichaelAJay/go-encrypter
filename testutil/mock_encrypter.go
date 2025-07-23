package testutil

import (
	"errors"
	"sync"

	"github.com/MichaelAJay/go-encrypter"
)

const (
	encryptedPrefix        = "encrypted:"
	hashedPasswordPrefix   = "hashedPassword:"
	hashedLookupDataPrefix = "hashedLookupData:"
)

type MockEncrypter struct {
	// Optional callback overrides for full test control
	EncryptCallbackFunc        func(data []byte) ([]byte, error)
	EncryptWithAADCallbackFunc func(data, aad []byte) ([]byte, error)
	DecryptCallbackFunc        func(data []byte) ([]byte, error)
	DecryptWithAADCallbackFunc func(data, aad []byte) ([]byte, error)
	HashPasswordCallbackFunc   func(password []byte) ([]byte, error)
	VerifyPasswordCallbackFunc func(hashed, password []byte) (bool, error)
	HashLookupDataCallbackFunc func(data []byte) []byte
	GetKeyVersionCallbackFunc  func() string

	// Call log (optional, for test assertions)
	mu            sync.Mutex
	EncryptCalls  [][]byte
	DecryptCalls  [][]byte
	PasswordCalls [][]byte
}

func NewMockEncrypter() *MockEncrypter {
	return &MockEncrypter{}
}

// Encrypt implements encrypter.Encrypter.
func (m *MockEncrypter) Encrypt(data []byte) ([]byte, error) {
	m.mu.Lock()
	m.EncryptCalls = append(m.EncryptCalls, data)
	m.mu.Unlock()

	if m.EncryptCallbackFunc != nil {
		return m.EncryptCallbackFunc(data)
	}
	return append([]byte(encryptedPrefix), data...), nil
}

// EncryptWithAAD implements encrypter.Encrypter.
func (m *MockEncrypter) EncryptWithAAD(data []byte, additionalData []byte) ([]byte, error) {
	if m.EncryptWithAADCallbackFunc != nil {
		return m.EncryptWithAADCallbackFunc(data, additionalData)
	}
	return append([]byte(encryptedPrefix), data...), nil
}

// Decrypt implements encrypter.Encrypter.
func (m *MockEncrypter) Decrypt(data []byte) ([]byte, error) {
	m.mu.Lock()
	m.DecryptCalls = append(m.DecryptCalls, data)
	m.mu.Unlock()

	if m.DecryptCallbackFunc != nil {
		return m.DecryptCallbackFunc(data)
	}

	if string(data[:10]) == encryptedPrefix {
		return data[10:], nil
	}

	return nil, errors.New("invalid ciphertext")
}

// DecryptWithAAD implements encrypter.Encrypter.
func (m *MockEncrypter) DecryptWithAAD(data []byte, additionalData []byte) ([]byte, error) {
	// todo
	panic("unimplemented")
}

// HashPassword implements encrypter.Encrypter.
func (m *MockEncrypter) HashPassword(password []byte) ([]byte, error) {
	m.mu.Lock()
	m.PasswordCalls = append(m.PasswordCalls, password)
	m.mu.Unlock()

	if m.HashPasswordCallbackFunc != nil {
		return m.HashPasswordCallbackFunc(password)
	}
	return append([]byte("hashed:"), password...), nil
}

// VerifyPassword implements encrypter.Encrypter.
func (m *MockEncrypter) VerifyPassword(hashedPassword []byte, password []byte) (bool, error) {
	if m.VerifyPasswordCallbackFunc != nil {
		return m.VerifyPasswordCallbackFunc(hashedPassword, password)
	}
	expected := append([]byte(hashedPasswordPrefix), password...)
	return string(expected) == string(hashedPassword), nil
}

// HashLookupData implements encrypter.Encrypter.
func (m *MockEncrypter) HashLookupData(data []byte) []byte {
	if m.HashLookupDataCallbackFunc != nil {
		return m.HashLookupDataCallbackFunc(data)
	}
	return append([]byte(hashedLookupDataPrefix), data...)
}

// GetKeyVersion implements encrypter.Encrypter.
func (m *MockEncrypter) GetKeyVersion() string {
	if m.GetKeyVersionCallbackFunc != nil {
		return m.GetKeyVersionCallbackFunc()
	}
	return "v1"
}

var _ encrypter.Encrypter = (*MockEncrypter)(nil)
