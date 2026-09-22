package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

const (
	totpStepSeconds = 30
	totpDigits      = 6
	replayTTL       = 90 * time.Second
)

// TOTPVerifier verifies TOTP codes against a shared secret and rejects
// replays by tracking which time-steps have already been consumed.
type TOTPVerifier struct {
	secret []byte

	mu       sync.Mutex
	consumed map[int64]time.Time // step -> expiry
}

func NewTOTPVerifier(secret []byte) *TOTPVerifier {
	return &TOTPVerifier{
		secret:   secret,
		consumed: make(map[int64]time.Time),
	}
}

// hotp computes the HOTP value (RFC 4226) for the given counter.
func hotp(secret []byte, counter uint64) string {
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(counterBytes[:])
	sum := mac.Sum(nil)

	offset := sum[19] & 0x0F
	binCode := (uint32(sum[offset]&0x7F) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	return fmt.Sprintf("%06d", binCode%1_000_000)
}

// totpStep returns the RFC 6238 time-step for t (T0=0, X=30s).
func totpStep(t time.Time) int64 {
	return t.Unix() / totpStepSeconds
}

// Verify checks code against the current time-step (±1 step for clock
// drift) and consumes that step so it can't be replayed.
func (v *TOTPVerifier) Verify(code string) bool {
	return v.verifyAt(code, time.Now())
}

// verifyAt is Verify with an injectable clock, so tests can pin "now"
// instead of racing the real clock.
func (v *TOTPVerifier) verifyAt(code string, now time.Time) bool {
	if len(code) != totpDigits {
		return false
	}

	current := totpStep(now)

	v.mu.Lock()
	defer v.mu.Unlock()

	v.purgeExpiredLocked(now)

	for _, s := range [...]int64{current - 1, current, current + 1} {
		if s < 0 {
			continue
		}
		want := hotp(v.secret, uint64(s))
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) != 1 {
			continue
		}
		if _, seen := v.consumed[s]; seen {
			return false // replay: this step was already spent
		}
		v.consumed[s] = now.Add(replayTTL)
		return true
	}

	return false
}

// purgeExpiredLocked drops consumed-step entries past their expiry, so the
// map doesn't grow without bound over the process's lifetime. Caller must
// hold v.mu.
func (v *TOTPVerifier) purgeExpiredLocked(now time.Time) {
	for s, expiry := range v.consumed {
		if !now.Before(expiry) {
			delete(v.consumed, s)
		}
	}
}
