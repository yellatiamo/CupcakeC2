package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/argon2"
)

// EncryptAES encrypts data using AES-256-GCM.
// Returns [Nonce (12 bytes) + Ciphertext]
func EncryptAES(plaintext []byte, key []byte) ([]byte, error) {
	// Ensure key is 32 bytes for AES-256
	fixedKey := make([]byte, 32)
	copy(fixedKey, key)

	block, err := aes.NewCipher(fixedKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	// Return Nonce + Ciphertext
	return append(nonce, ciphertext...), nil
}

// DecryptAES decrypts data encrypted with AES-256-GCM.
// Expects [Nonce (12 bytes) + Ciphertext]
func DecryptAES(data []byte, key []byte) ([]byte, error) {
	if len(data) < 12 {
		return nil, errors.New("ciphertext too short")
	}

	fixedKey := make([]byte, 32)
	copy(fixedKey, key)

	block, err := aes.NewCipher(fixedKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("invalid data size")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DeriveKey implements Argon2id (memory-hard KDF) to derive a 32-byte AES key.
// Parameters: time=3, memory=64MB, threads=4.
//
// NOTE: The Rust agent currently uses DeriveKeyAgent (SHA256×100k) for get_aes_key().
// Prefer DeriveKeyAgent when packing CKMS / anything the agent verifies with get_aes_key().
// Argon2 remains for server-side static session material where both ends are Go.
func DeriveKey(baseKey []byte, salt []byte) []byte {
	if len(salt) == 0 {
		// If no salt, still hash through Argon2id with a fixed zero salt
		// (not ideal, but backward compatible). Caller should always provide salt.
		salt = make([]byte, 32)
	}
	return argon2.IDKey(baseKey, salt, 3, 64*1024, 4, 32)
}

// agentKDFIterations must match Client/core/src/crypto.rs KDF_ITERATIONS.
const agentKDFIterations = uint32(100_000)

// DeriveKeyAgent matches Rust `crypto::derive_key` used by get_aes_key():
//
//	dk0 = SHA256(base || salt32)
//	dki = SHA256(dk || i_le32 || base || salt)  for i in 0..100_000
//
// Empty salt → 32 zero bytes (same as Rust when salt.is_empty()).
func DeriveKeyAgent(baseKey, salt []byte) []byte {
	saltUsed := salt
	if len(saltUsed) == 0 {
		saltUsed = make([]byte, 32)
	}
	// Pad/truncate salt to what callers typically pass (32); Rust resizes salt to 32
	// before calling derive_key, so accept any length as-is once non-empty.
	h := sha256.New()
	h.Write(baseKey)
	h.Write(saltUsed)
	dk := h.Sum(nil)

	var ctr [4]byte
	for i := uint32(0); i < agentKDFIterations; i++ {
		binary.LittleEndian.PutUint32(ctr[:], i)
		h = sha256.New()
		h.Write(dk)
		h.Write(ctr[:])
		h.Write(baseKey)
		h.Write(saltUsed)
		dk = h.Sum(nil)
	}
	return dk
}

// ObfuscatePacket applies secondary obfuscation to encrypted data.
// Supported modes: base64, junk, padding, none.
// "xor" mode removed (repeating-key XOR leaks key material via frequency analysis).
//
// padding = client apply_tailored_padding: [ciphertext][rand 50..2048][orig_len u32 BE]
// junk    = [ciphertext][rand 8..64][orig_len u32 BE]
func ObfuscatePacket(data []byte, mode string, key []byte) []byte {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "base64":
		return []byte(base64.StdEncoding.EncodeToString(data))
	case "junk":
		return appendLenPrefixedPadding(data, randInt(8, 64))
	case "padding":
		// Match Client/core crypto::apply_tailored_padding (50–2048 random + u32 BE len)
		return appendLenPrefixedPadding(data, randInt(50, 2048+1))
	default:
		// "none"/empty: pure ciphertext
		return data
	}
}

// appendLenPrefixedPadding: [data][junk N][len(data) as u32 BE]
func appendLenPrefixedPadding(data []byte, junkLen int) []byte {
	if junkLen < 1 {
		junkLen = 8
	}
	originalLen := uint32(len(data))
	junk := make([]byte, junkLen)
	_, _ = rand.Read(junk)
	out := make([]byte, len(data)+junkLen+4)
	copy(out, data)
	copy(out[len(data):], junk)
	binary.BigEndian.PutUint32(out[len(out)-4:], originalLen)
	return out
}

// DeobfuscatePacket reverses the obfuscation.
func DeobfuscatePacket(data []byte, mode string, key []byte) []byte {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return data
		}
		return decoded
	case "junk", "padding":
		// Same wire layout as Client (u32 BE original length trailer)
		return RemoveTailoredPadding(data)
	default:
		// "none"/empty: pure ciphertext. Do NOT strip padding here.
		return data
	}
}

// RemoveTailoredPadding strips client padding/junk:
// [ciphertext][random…][original_len u32 BE]. Safe if trailer is nonsense.
func RemoveTailoredPadding(data []byte) []byte {
	if len(data) < 4 {
		return data
	}
	originalLen := binary.BigEndian.Uint32(data[len(data)-4:])
	if originalLen == 0 || int(originalLen) > len(data)-4 {
		return data
	}
	return data[:originalLen]
}

// RemoveDefaultPadding strips the legacy small-padding format:
// [ciphertext][junk N bytes][N as u16 BE], N in 1..16.
func RemoveDefaultPadding(data []byte) []byte {
	if len(data) < 2 {
		return data
	}
	padLen := int(binary.BigEndian.Uint16(data[len(data)-2:]))
	if padLen < 1 || padLen > 16 {
		return data
	}
	if len(data) < 2+padLen {
		return data
	}
	return data[:len(data)-2-padLen]
}

// DecryptAESWithCompat tries DecryptAES; on GCM failure, retries after stripping
// tailored padding and legacy u16 padding (agent/server mode mismatch recovery).
func DecryptAESWithCompat(data []byte, key []byte) ([]byte, error) {
	plain, err := DecryptAES(data, key)
	if err == nil {
		return plain, nil
	}
	for _, stripped := range [][]byte{
		RemoveTailoredPadding(data),
		RemoveDefaultPadding(data),
	} {
		if len(stripped) == len(data) || len(stripped) == 0 {
			continue
		}
		if plain2, err2 := DecryptAES(stripped, key); err2 == nil {
			return plain2, nil
		}
	}
	return nil, err
}

// randInt returns a uniformly random integer in [min, max) using crypto/rand
// with rejection sampling to avoid modulo bias.
func randInt(min, max int) int {
	if min >= max {
		return min
	}
	n := big.NewInt(int64(max - min))
	r, err := rand.Int(rand.Reader, n)
	if err != nil {
		// Fallback: use modulo with full uint32 (still better than single byte)
		var b [4]byte
		_, _ = rand.Read(b[:])
		v := binary.BigEndian.Uint32(b[:])
		return min + int(v%uint32(max-min))
	}
	return min + int(r.Int64())
}

// RandomAlphaString generates a cryptographically random alphabetic string of given length.
func RandomAlphaString(length int) (string, error) {
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result := make([]byte, length)
	if _, err := rand.Read(result); err != nil {
		return "", err
	}
	for i, b := range result {
		result[i] = charset[int(b)%len(charset)]
	}
	return string(result), nil
}
