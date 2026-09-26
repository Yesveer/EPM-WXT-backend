package logmanager

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const encVersion = byte(0x02) // distinct from agent-config version (0x01)

func deriveKey() ([]byte, error) {
	secret := strings.TrimSpace(os.Getenv("GATEWAY_SECRET"))
	if secret == "" {
		return nil, fmt.Errorf("GATEWAY_SECRET env var not set")
	}
	salt := []byte("vsay-logmanager-creds-enc-v1")
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(secret))
	prk := mac.Sum(nil)

	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte("vsay-logmanager-v1"))
	mac.Write([]byte{0x01})
	return mac.Sum(nil), nil // 32 bytes = AES-256
}

// EncryptCreds marshals v to JSON then AES-256-GCM encrypts it.
func EncryptCreds(v any) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	key, err := deriveKey()
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	out := make([]byte, 1+len(nonce)+len(ct))
	out[0] = encVersion
	copy(out[1:], nonce)
	copy(out[1+len(nonce):], ct)
	return out, nil
}

// DecryptCreds decrypts and JSON-unmarshals into v.
func DecryptCreds(encrypted []byte, v any) error {
	if len(encrypted) < 1 || encrypted[0] != encVersion {
		return fmt.Errorf("unsupported creds format version %d", encrypted[0])
	}
	key, err := deriveKey()
	if err != nil {
		return err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return err
	}
	data := encrypted[1:]
	if len(data) < gcm.NonceSize() {
		return fmt.Errorf("encrypted creds too short")
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong key or tampered): %w", err)
	}
	return json.Unmarshal(plain, v)
}
