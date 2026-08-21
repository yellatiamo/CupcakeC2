package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// =============================================================================
// X25519 ECDH handshake with PSK MAC authentication (v2)
// Wire: version(1)=0x02 || public_key(32) || psk_mac(16)  → 49 bytes each way
// psk_mac = HMAC-SHA256(psk, domain||pubkeys)[:16]
// Session key: HKDF-SHA256(ikm=shared_secret, salt=psk, info=WireIDs.NoiseInfo)
// =============================================================================

const (
	NoiseVersion byte = 0x02
	NoiseMacLen       = 16
	NoiseMsgLen       = 1 + 32 + NoiseMacLen // 49
)

// noiseInitDom / noiseRespDom are seed-derived (must match client wire_ids).
func noiseInitDom() []byte {
	return GetWireIDs().NoiseInitDom
}
func noiseRespDom() []byte {
	return GetWireIDs().NoiseRespDom
}

// NoiseInfoBytes returns build-seed derived HKDF info (not a product string).
func NoiseInfoBytes() []byte {
	return GetWireIDs().NoiseInfo
}

// EphemeralKey is an X25519 key pair.
type EphemeralKey struct {
	Secret [32]byte
	Public [32]byte
}

// GenerateEphemeralKey creates a random X25519 key pair.
func GenerateEphemeralKey() (*EphemeralKey, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, fmt.Errorf("rand.Read failed: %w", err)
	}
	// Clamp for X25519
	secret[0] &= 248
	secret[31] &= 127
	secret[31] |= 64

	var public [32]byte
	curve25519.ScalarBaseMult(&public, &secret)
	return &EphemeralKey{Secret: secret, Public: public}, nil
}

// ecdhShared computes X25519(local_secret, peer_public).
func ecdhShared(localSecret, peerPublic *[32]byte) ([32]byte, error) {
	var shared [32]byte
	curve25519.ScalarMult(&shared, localSecret, peerPublic)
	// Reject all-zero shared secret (low-order points)
	var zero [32]byte
	if shared == zero {
		return zero, fmt.Errorf("invalid ECDH shared secret (zero)")
	}
	return shared, nil
}

// deriveSessionKeyHKDF derives 32-byte AES key from ECDH shared + PSK.
func deriveSessionKeyHKDF(sharedSecret, psk []byte) ([32]byte, error) {
	r := hkdf.New(sha256.New, sharedSecret, psk, NoiseInfoBytes())
	var sk [32]byte
	if _, err := io.ReadFull(r, sk[:]); err != nil {
		return [32]byte{}, err
	}
	return sk, nil
}

func noisePSKMac(psk, domain []byte, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write(domain)
	for _, p := range parts {
		mac.Write(p)
	}
	sum := mac.Sum(nil)
	return sum[:NoiseMacLen]
}

// NoiseInitiate builds a client handshake message (for tests / tooling).
func NoiseInitiate(psk []byte) (e *EphemeralKey, msg []byte, err error) {
	if len(psk) == 0 {
		return nil, nil, fmt.Errorf("noise psk required")
	}
	e, err = GenerateEphemeralKey()
	if err != nil {
		return nil, nil, err
	}
	m := noisePSKMac(psk, noiseInitDom(), e.Public[:])
	msg = make([]byte, NoiseMsgLen)
	msg[0] = NoiseVersion
	copy(msg[1:33], e.Public[:])
	copy(msg[33:49], m)
	return e, msg, nil
}

// NoiseComplete finishes client side after server response (verifies PSK MAC).
func NoiseComplete(local *EphemeralKey, serverMsg, psk []byte) ([32]byte, error) {
	var zero [32]byte
	if len(psk) == 0 {
		return zero, fmt.Errorf("noise psk required")
	}
	if len(serverMsg) != NoiseMsgLen {
		return zero, fmt.Errorf("invalid server handshake length: %d", len(serverMsg))
	}
	if serverMsg[0] != NoiseVersion {
		return zero, fmt.Errorf("unsupported noise version: 0x%02x", serverMsg[0])
	}
	var serverPub [32]byte
	copy(serverPub[:], serverMsg[1:33])
	expect := noisePSKMac(psk, noiseRespDom(), local.Public[:], serverPub[:])
	if subtle.ConstantTimeCompare(serverMsg[33:49], expect) != 1 {
		return zero, fmt.Errorf("noise psk auth failed (server mac)")
	}
	shared, err := ecdhShared(&local.Secret, &serverPub)
	if err != nil {
		return zero, err
	}
	return deriveSessionKeyHKDF(shared[:], psk)
}

// NoiseRespond processes client handshake (49-byte v2 with PSK MAC).
// Returns (serverResponse 49 bytes, sessionKey, error).
func NoiseRespond(clientMsg []byte, psk []byte) ([]byte, [32]byte, error) {
	var zero [32]byte
	if len(psk) == 0 {
		return nil, zero, fmt.Errorf("noise psk required")
	}
	if len(clientMsg) != NoiseMsgLen {
		return nil, zero, fmt.Errorf("invalid handshake length: %d (want %d X25519+mac)", len(clientMsg), NoiseMsgLen)
	}
	if clientMsg[0] != NoiseVersion {
		return nil, zero, fmt.Errorf("unsupported noise version: 0x%02x", clientMsg[0])
	}

	var clientPublic [32]byte
	copy(clientPublic[:], clientMsg[1:33])
	expectMac := noisePSKMac(psk, noiseInitDom(), clientPublic[:])
	if subtle.ConstantTimeCompare(clientMsg[33:49], expectMac) != 1 {
		return nil, zero, fmt.Errorf("noise psk auth failed (client mac)")
	}

	e, err := GenerateEphemeralKey()
	if err != nil {
		return nil, zero, err
	}

	shared, err := ecdhShared(&e.Secret, &clientPublic)
	if err != nil {
		return nil, zero, err
	}
	sessionKey, err := deriveSessionKeyHKDF(shared[:], psk)
	if err != nil {
		return nil, zero, err
	}

	respMac := noisePSKMac(psk, noiseRespDom(), clientPublic[:], e.Public[:])
	resp := make([]byte, NoiseMsgLen)
	resp[0] = NoiseVersion
	copy(resp[1:33], e.Public[:])
	copy(resp[33:49], respMac)
	return resp, sessionKey, nil
}

// NoiseEncrypt encrypts plaintext with the session key (AES-256-GCM wrapper).
func NoiseEncrypt(sessionKey [32]byte, plaintext []byte) ([]byte, error) {
	return EncryptAES(plaintext, sessionKey[:])
}

// NoiseDecrypt decrypts ciphertext with the session key (AES-256-GCM wrapper).
func NoiseDecrypt(sessionKey [32]byte, ciphertext []byte) ([]byte, error) {
	return DecryptAES(ciphertext, sessionKey[:])
}
