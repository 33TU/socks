package shadowsocks

import (
	"crypto/aes"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"github.com/zeebo/blake3"
)

// blake3IdentitySubkeyContext is the context string used to derive the subkey
// that encrypts a TCP identity header.
const blake3IdentitySubkeyContext = "shadowsocks 2022 identity subkey"

// IdentityHeaderLen is the size of one identity header: a single AES block.
const IdentityHeaderLen = 16

// Errors from identity header processing.
var (
	ErrUnknownUser         = errors.New("identity header does not name a known user")
	ErrMissingIdentityPSKs = errors.New("missing identity PSKs")
)

// Identity headers let one server serve many users on one port, and let relays
// forward by user without holding the keys that protect the traffic.
//
// A client is issued a chain of keys, written iPSK0:iPSK1:uPSK in a URL. Each
// identity PSK gets a header naming the hash of the key after it, so every hop
// learns only which key comes next, and the last key, the user PSK, is what
// actually encrypts the session.
//
// PSKHash returns the 16 bytes that name a key: the start of its BLAKE3 hash.
func PSKHash(psk []byte) [IdentityHeaderLen]byte {
	sum := blake3.Sum256(psk)

	var hash [IdentityHeaderLen]byte
	copy(hash[:], sum[:IdentityHeaderLen])

	return hash
}

// DeriveIdentitySubkeyTo derives the subkey that encrypts a TCP identity
// header, which is bound to the request's salt so the header differs per
// session. UDP identity headers use the identity PSK directly instead, and are
// varied by the session and packet ID.
func DeriveIdentitySubkeyTo(dst []byte, method Method, identityPSK, salt []byte) error {
	if err := method.Validate(); err != nil {
		return err
	}
	if len(salt) != method.SaltSize {
		return fmt.Errorf("invalid salt length: got %d, want %d", len(salt), method.SaltSize)
	}

	h := blake3.NewDeriveKey(blake3IdentitySubkeyContext)
	if _, err := h.Write(identityPSK); err != nil {
		return fmt.Errorf("derive identity subkey: %w", err)
	}
	if _, err := h.Write(salt); err != nil {
		return fmt.Errorf("derive identity subkey: %w", err)
	}

	sum := h.Sum(nil)
	if len(dst) != method.KeySize {
		return fmt.Errorf("invalid subkey length: got %d, want %d", len(dst), method.KeySize)
	}
	copy(dst, sum[:method.KeySize])

	return nil
}

// EncodeTCPIdentityHeadersTo appends one identity header per identity PSK to
// dst, each naming the key that follows it.
//
// psk is the user PSK the session itself uses, which the last header names.
func EncodeTCPIdentityHeadersTo(dst []byte, method Method, identityPSKs [][]byte, psk, salt []byte) ([]byte, error) {
	if err := method.Validate(); err != nil {
		return nil, err
	}

	subkey := make([]byte, method.KeySize)

	for i, identityPSK := range identityPSKs {
		// Each header names the next key in the chain; the last names the user.
		next := psk
		if i+1 < len(identityPSKs) {
			next = identityPSKs[i+1]
		}

		if err := DeriveIdentitySubkeyTo(subkey, method, identityPSK, salt); err != nil {
			return nil, err
		}

		block, err := aes.NewCipher(subkey)
		if err != nil {
			return nil, fmt.Errorf("create identity cipher: %w", err)
		}

		hash := PSKHash(next)
		header := make([]byte, IdentityHeaderLen)
		block.Encrypt(header, hash[:])

		dst = append(dst, header...)
	}

	return dst, nil
}

// DecodeTCPIdentityHeader decrypts one TCP identity header and returns the hash
// of the key it names.
func DecodeTCPIdentityHeader(header []byte, method Method, identityPSK, salt []byte) ([IdentityHeaderLen]byte, error) {
	var named [IdentityHeaderLen]byte

	if len(header) != IdentityHeaderLen {
		return named, fmt.Errorf("invalid identity header length: got %d, want %d", len(header), IdentityHeaderLen)
	}

	subkey := make([]byte, method.KeySize)
	if err := DeriveIdentitySubkeyTo(subkey, method, identityPSK, salt); err != nil {
		return named, err
	}

	block, err := aes.NewCipher(subkey)
	if err != nil {
		return named, fmt.Errorf("create identity cipher: %w", err)
	}

	block.Decrypt(named[:], header)
	return named, nil
}

// EncodeUDPIdentityHeadersTo appends one identity header per identity PSK to dst.
//
// UDP headers differ from TCP's: the key is the identity PSK itself rather than
// a subkey, and the named hash is masked with the packet's session and packet
// ID so that the header differs from packet to packet.
//
// separateHeader is the plaintext session and packet ID, before it is encrypted.
func EncodeUDPIdentityHeadersTo(dst []byte, identityPSKs [][]byte, psk, separateHeader []byte) ([]byte, error) {
	if len(separateHeader) != UDPSeparateHeaderLen {
		return nil, fmt.Errorf("invalid separate header length: got %d, want %d", len(separateHeader), UDPSeparateHeaderLen)
	}

	for i, identityPSK := range identityPSKs {
		next := psk
		if i+1 < len(identityPSKs) {
			next = identityPSKs[i+1]
		}

		block, err := aes.NewCipher(identityPSK)
		if err != nil {
			return nil, fmt.Errorf("create identity cipher: %w", err)
		}

		hash := PSKHash(next)
		var plaintext [IdentityHeaderLen]byte
		subtle.XORBytes(plaintext[:], hash[:], separateHeader)

		header := make([]byte, IdentityHeaderLen)
		block.Encrypt(header, plaintext[:])

		dst = append(dst, header...)
	}

	return dst, nil
}

// DecodeUDPIdentityHeader decrypts one UDP identity header and returns the hash
// of the key it names.
//
// separateHeader is the plaintext session and packet ID, which masked the hash.
func DecodeUDPIdentityHeader(header []byte, identityPSK, separateHeader []byte) ([IdentityHeaderLen]byte, error) {
	var named [IdentityHeaderLen]byte

	if len(header) != IdentityHeaderLen {
		return named, fmt.Errorf("invalid identity header length: got %d, want %d", len(header), IdentityHeaderLen)
	}
	if len(separateHeader) != UDPSeparateHeaderLen {
		return named, fmt.Errorf("invalid separate header length: got %d, want %d", len(separateHeader), UDPSeparateHeaderLen)
	}

	block, err := aes.NewCipher(identityPSK)
	if err != nil {
		return named, fmt.Errorf("create identity cipher: %w", err)
	}

	var masked [IdentityHeaderLen]byte
	block.Decrypt(masked[:], header)
	subtle.XORBytes(named[:], masked[:], separateHeader)

	return named, nil
}

// User is one user of a multi-user server.
type User struct {
	Name string
	PSK  []byte
}

// UserTable maps the hash carried in an identity header to the user it names,
// so a server can serve many users on one port.
//
// A UserTable is safe for concurrent use.
type UserTable struct {
	mu    sync.RWMutex
	users map[[IdentityHeaderLen]byte]User
}

// NewUserTable creates an empty user table.
func NewUserTable() *UserTable {
	return &UserTable{users: make(map[[IdentityHeaderLen]byte]User)}
}

// Add registers a user by their PSK.
func (t *UserTable) Add(name string, method Method, psk []byte) error {
	if err := method.Validate(); err != nil {
		return err
	}
	if len(psk) != method.KeySize {
		return fmt.Errorf("invalid PSK length for user %s: got %d, want %d", name, len(psk), method.KeySize)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.users == nil {
		t.users = make(map[[IdentityHeaderLen]byte]User)
	}
	t.users[PSKHash(psk)] = User{Name: name, PSK: append([]byte(nil), psk...)}

	return nil
}

// AddBase64 registers a user whose PSK is base64 encoded.
func (t *UserTable) AddBase64(name string, method Method, psk string) error {
	key, err := DecodePSKTo(nil, method, psk)
	if err != nil {
		return fmt.Errorf("invalid PSK for user %s: %w", name, err)
	}

	return t.Add(name, method, key)
}

// Remove deletes a user by name.
func (t *UserTable) Remove(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for hash, user := range t.users {
		if user.Name == name {
			delete(t.users, hash)
		}
	}
}

// Lookup returns the user an identity header names.
func (t *UserTable) Lookup(hash [IdentityHeaderLen]byte) (User, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	user, ok := t.users[hash]
	return user, ok
}

// Len returns the number of registered users.
func (t *UserTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return len(t.users)
}
