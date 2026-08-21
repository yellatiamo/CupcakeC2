package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"cupcake-server/internal/model"

	"gorm.io/gorm"
)

const (
	// DefaultSessionTTLHours is used when CUPCAKE_SESSION_TTL_HOURS is unset/invalid.
	DefaultSessionTTLHours = 24
	// MaxConcurrentSessions per user; oldest active sessions are revoked when exceeded.
	MaxConcurrentSessions = 10
	// touchThrottle avoids writing LastSeenAt on every authenticated request.
	touchThrottle = time.Minute
)

var (
	// ErrSessionInvalid is returned when the raw token does not map to a usable session.
	ErrSessionInvalid = errors.New("session invalid")
)

// HashSessionToken returns the sha256 hex digest of a raw bearer token.
func HashSessionToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// SessionTTL returns the configured panel session lifetime.
// Override with CUPCAKE_SESSION_TTL_HOURS (positive integer hours).
func SessionTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv("CUPCAKE_SESSION_TTL_HOURS"))
	if raw == "" {
		return time.Duration(DefaultSessionTTLHours) * time.Hour
	}
	h, err := strconv.Atoi(raw)
	if err != nil || h <= 0 {
		return time.Duration(DefaultSessionTTLHours) * time.Hour
	}
	return time.Duration(h) * time.Hour
}

// CreateSession stores a new session (hash only) and returns the same raw token
// for the caller to hand to the client once. Enforces MaxConcurrentSessions.
func CreateSession(userID uint, rawToken, ip, ua string, ttl time.Duration) (*model.Session, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if rawToken == "" {
		return nil, fmt.Errorf("empty session token")
	}
	if ttl <= 0 {
		ttl = SessionTTL()
	}
	now := time.Now()
	sess := &model.Session{
		TokenHash:  HashSessionToken(rawToken),
		UserID:     userID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
		LastSeenAt: now,
		IP:         ip,
		UserAgent:  truncateUA(ua),
	}
	if err := DB.Create(sess).Error; err != nil {
		return nil, err
	}
	_ = enforceMaxSessions(userID)
	return sess, nil
}

// LookupSession resolves a raw bearer token to a session + active user.
// Returns ErrSessionInvalid when missing, revoked, expired, or user inactive.
func LookupSession(rawToken string) (*model.Session, *model.User, error) {
	if DB == nil || rawToken == "" {
		return nil, nil, ErrSessionInvalid
	}
	hash := HashSessionToken(rawToken)
	var sess model.Session
	if err := DB.Where("token_hash = ?", hash).First(&sess).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrSessionInvalid
		}
		return nil, nil, err
	}
	if sess.RevokedAt != nil {
		return nil, nil, ErrSessionInvalid
	}
	if !sess.ExpiresAt.After(time.Now()) {
		return nil, nil, ErrSessionInvalid
	}
	var user model.User
	if err := DB.First(&user, sess.UserID).Error; err != nil {
		return nil, nil, ErrSessionInvalid
	}
	if !user.IsActive {
		return nil, nil, ErrSessionInvalid
	}
	return &sess, &user, nil
}

// TouchSession updates LastSeenAt when the previous stamp is older than touchThrottle.
func TouchSession(id uint) {
	if DB == nil || id == 0 {
		return
	}
	now := time.Now()
	// Only update rows whose last_seen is older than the throttle window.
	_ = DB.Model(&model.Session{}).
		Where("id = ? AND last_seen_at < ?", id, now.Add(-touchThrottle)).
		Update("last_seen_at", now).Error
}

// RevokeSession marks the session for the given raw token as revoked.
func RevokeSession(rawToken string) error {
	if DB == nil || rawToken == "" {
		return nil
	}
	now := time.Now()
	return DB.Model(&model.Session{}).
		Where("token_hash = ? AND revoked_at IS NULL", HashSessionToken(rawToken)).
		Update("revoked_at", now).Error
}

// RevokeAllUserSessions revokes every non-revoked session for the user.
func RevokeAllUserSessions(userID uint) error {
	if DB == nil || userID == 0 {
		return nil
	}
	now := time.Now()
	return DB.Model(&model.Session{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", now).Error
}

// enforceMaxSessions keeps at most MaxConcurrentSessions active sessions per user.
func enforceMaxSessions(userID uint) error {
	if DB == nil || userID == 0 {
		return nil
	}
	now := time.Now()
	var active []model.Session
	if err := DB.Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", userID, now).
		Order("created_at asc").
		Find(&active).Error; err != nil {
		return err
	}
	if len(active) <= MaxConcurrentSessions {
		return nil
	}
	// Revoke oldest until under the cap.
	overflow := len(active) - MaxConcurrentSessions
	ids := make([]uint, 0, overflow)
	for i := 0; i < overflow; i++ {
		ids = append(ids, active[i].ID)
	}
	return DB.Model(&model.Session{}).
		Where("id IN ?", ids).
		Update("revoked_at", now).Error
}

func truncateUA(ua string) string {
	const max = 512
	if len(ua) <= max {
		return ua
	}
	return ua[:max]
}

