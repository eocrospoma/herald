package main

import (
	"testing"
	"time"
)

// rfc4226Secret is the shared secret used by both the RFC 4226 and RFC 6238
// published test vectors: the ASCII string "12345678901234567890".
var rfc4226Secret = []byte("12345678901234567890")

// TestHOTP_RFC4226Vectors checks hotp() against RFC 4226 Appendix D,
// counters 0 through 9.
func TestHOTP_RFC4226Vectors(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}

	for counter, expected := range want {
		got := hotp(rfc4226Secret, uint64(counter))
		if got != expected {
			t.Errorf("hotp(counter=%d) = %q, want %q", counter, got, expected)
		}
	}
}

// TestTOTP_RFC6238Vectors checks verifyAt() against RFC 6238 Appendix B's
// SHA1 test values. The RFC's published codes are 8-digit (mod 10^8); our
// implementation truncates to 6 digits (mod 10^6), which are the low 6
// digits of the same value, so expected codes are derived from the RFC's
// 8-digit ones rather than duplicated by hand.
func TestTOTP_RFC6238Vectors(t *testing.T) {
	cases := []struct {
		unixTime int64
		rfc8     string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, c := range cases {
		want := c.rfc8[len(c.rfc8)-6:]
		v := NewTOTPVerifier(rfc4226Secret)
		now := time.Unix(c.unixTime, 0).UTC()
		if !v.verifyAt(want, now) {
			t.Errorf("verifyAt(%q, t=%d) = false, want true", want, c.unixTime)
		}
	}
}

func TestVerify_RejectsWrongCode(t *testing.T) {
	v := NewTOTPVerifier(rfc4226Secret)
	now := time.Unix(59, 0).UTC()

	if v.verifyAt("000000", now) {
		t.Fatal("verifyAt accepted an incorrect code")
	}
}

func TestVerify_RejectsWrongLength(t *testing.T) {
	v := NewTOTPVerifier(rfc4226Secret)
	now := time.Unix(59, 0).UTC()

	for _, bad := range []string{"", "12345", "1234567"} {
		if v.verifyAt(bad, now) {
			t.Fatalf("verifyAt(%q) accepted, want rejected (wrong length)", bad)
		}
	}
}

func TestVerify_AcceptsClockDriftWithinTolerance(t *testing.T) {
	// Step for t=59 is 1 (59/30). A code generated for step 1 must still
	// verify one step early or late (±30s), the documented drift window.
	code := hotp(rfc4226Secret, 1)

	if !NewTOTPVerifier(rfc4226Secret).verifyAt(code, time.Unix(89, 0).UTC()) {
		t.Error("code for step 1 rejected one step later (t=89), want accepted")
	}
	if !NewTOTPVerifier(rfc4226Secret).verifyAt(code, time.Unix(29, 0).UTC()) {
		t.Error("code for step 1 rejected one step earlier (t=29), want accepted")
	}
}

func TestVerify_RejectsOutsideToleranceWindow(t *testing.T) {
	code := hotp(rfc4226Secret, 1) // valid only for steps 0, 1, 2

	v := NewTOTPVerifier(rfc4226Secret)
	// t=150 is step 5 - four steps away from step 1, outside ±1 tolerance.
	if v.verifyAt(code, time.Unix(150, 0).UTC()) {
		t.Fatal("verifyAt accepted a code far outside the tolerance window")
	}
}

func TestVerify_RejectsReplayOfSameStep(t *testing.T) {
	code := hotp(rfc4226Secret, 1)
	now := time.Unix(59, 0).UTC()

	v := NewTOTPVerifier(rfc4226Secret)
	if !v.verifyAt(code, now) {
		t.Fatal("first use of code rejected, want accepted")
	}
	if v.verifyAt(code, now) {
		t.Fatal("replay of the same code/step accepted, want rejected")
	}
}

func TestVerify_ReplayRejectedEvenFromNeighboringStep(t *testing.T) {
	// Once step 1 is consumed, presenting the same code again one step
	// later must still fail - it resolves to the same already-spent step,
	// not a fresh one.
	code := hotp(rfc4226Secret, 1)
	v := NewTOTPVerifier(rfc4226Secret)

	if !v.verifyAt(code, time.Unix(59, 0).UTC()) {
		t.Fatal("first use of code rejected, want accepted")
	}
	if v.verifyAt(code, time.Unix(89, 0).UTC()) {
		t.Fatal("replay via a neighboring step accepted, want rejected")
	}
}

func TestPurgeExpired_RemovesOldConsumedSteps(t *testing.T) {
	code := hotp(rfc4226Secret, 1)
	first := time.Unix(59, 0).UTC()

	v := NewTOTPVerifier(rfc4226Secret)
	if !v.verifyAt(code, first) {
		t.Fatal("first use rejected, want accepted")
	}
	if len(v.consumed) != 1 {
		t.Fatalf("consumed map has %d entries after one use, want 1", len(v.consumed))
	}

	// Any later Verify call purges expired entries as a side effect, so the
	// map doesn't grow without bound over the process's lifetime.
	later := first.Add(replayTTL + time.Second)
	v.verifyAt("000000", later)

	if len(v.consumed) != 0 {
		t.Fatalf("consumed map has %d entries after expiry, want 0 (purged)", len(v.consumed))
	}
}
