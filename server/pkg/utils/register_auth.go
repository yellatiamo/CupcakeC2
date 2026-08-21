package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// regProofDomain returns the seed-derived register proof domain (matches client wire_ids).
func regProofDomain() []byte {
	return GetWireIDs().RegProofDomain
}

// ComputeRegisterProof returns base64(HMAC-SHA256(sessionKey, domain||uuid)).
func ComputeRegisterProof(sessionKey []byte, agentUUID string) string {
	mac := hmac.New(sha256.New, sessionKey)
	mac.Write(regProofDomain())
	mac.Write([]byte(agentUUID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyRegisterProof checks a base64 HMAC register proof (constant-time).
// Empty/missing proof or wrong key/uuid always fails.
func VerifyRegisterProof(sessionKey []byte, agentUUID, proofB64 string) bool {
	if len(sessionKey) == 0 || strings.TrimSpace(agentUUID) == "" {
		return false
	}
	proofB64 = strings.TrimSpace(proofB64)
	if proofB64 == "" {
		return false
	}
	got, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil || len(got) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, sessionKey)
	mac.Write(regProofDomain())
	mac.Write([]byte(agentUUID))
	expect := mac.Sum(nil)
	return subtle.ConstantTimeCompare(got, expect) == 1
}
