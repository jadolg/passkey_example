package storage

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrCredentialNotFound = errors.New("credential not found")
	ErrLastCredential     = errors.New("cannot remove last credential")
)

// NamedCredential wraps a WebAuthn credential with a name
type NamedCredential struct {
	Name       string              `json:"name"`
	Credential webauthn.Credential `json:"credential"`
}

// User represents a user with WebAuthn credentials
type User struct {
	ID          []byte            `json:"id"`
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	Passkeys    []NamedCredential `json:"passkeys"`
}

// WebAuthnID implements webauthn.User interface
func (u *User) WebAuthnID() []byte {
	return u.ID
}

// WebAuthnName implements webauthn.User interface
func (u *User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName implements webauthn.User interface
func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnCredentials implements webauthn.User interface
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, len(u.Passkeys))
	for i, nc := range u.Passkeys {
		creds[i] = nc.Credential
	}
	return creds
}

// AddCredential adds a named credential to the user
func (u *User) AddCredential(name string, cred webauthn.Credential) {
	u.Passkeys = append(u.Passkeys, NamedCredential{
		Name:       name,
		Credential: cred,
	})
}

// GetPasskeyList returns a list of passkey IDs and names
func (u *User) GetPasskeyList() []map[string]string {
	list := make([]map[string]string, len(u.Passkeys))
	for i, nc := range u.Passkeys {
		list[i] = map[string]string{
			"id":   base64.URLEncoding.EncodeToString(nc.Credential.ID),
			"name": nc.Name,
		}
	}
	return list
}

// RemoveCredential removes a credential by ID (base64 encoded)
func (u *User) RemoveCredential(credentialID string) error {
	if len(u.Passkeys) <= 1 {
		return ErrLastCredential
	}

	for i, nc := range u.Passkeys {
		if base64.URLEncoding.EncodeToString(nc.Credential.ID) == credentialID {
			u.Passkeys = append(u.Passkeys[:i], u.Passkeys[i+1:]...)
			return nil
		}
	}
	return ErrCredentialNotFound
}

// RenameCredential renames a credential by ID
func (u *User) RenameCredential(credentialID, newName string) error {
	for i, nc := range u.Passkeys {
		if base64.URLEncoding.EncodeToString(nc.Credential.ID) == credentialID {
			u.Passkeys[i].Name = newName
			return nil
		}
	}
	return ErrCredentialNotFound
}

// Store handles file-based user storage
type Store struct {
	mu       sync.RWMutex
	filePath string
	users    map[string]*User
}

// NewStore creates a new user store
func NewStore(filePath string) (*Store, error) {
	s := &Store{
		filePath: filePath,
		users:    make(map[string]*User),
	}

	// Try to load existing users
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return s, nil
}

// load reads users from file
func (s *Store) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &s.users)
}

// save writes users to file
func (s *Store) save() error {
	data, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.filePath, data, 0644)
}

// GetUser retrieves a user by name
func (s *Store) GetUser(name string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[name]
	if !ok {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// CreateUser creates a new user (trust on first contact)
func (s *Store) CreateUser(name string, id []byte) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if user already exists
	if _, ok := s.users[name]; ok {
		return nil, ErrUserExists
	}

	user := &User{
		ID:          id,
		Name:        name,
		DisplayName: name,
		Passkeys:    []NamedCredential{},
	}

	s.users[name] = user

	if err := s.save(); err != nil {
		delete(s.users, name)
		return nil, err
	}

	return user, nil
}

// UpdateUser updates an existing user
func (s *Store) UpdateUser(user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[user.Name]; !ok {
		return ErrUserNotFound
	}

	s.users[user.Name] = user

	return s.save()
}
