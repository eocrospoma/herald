package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"sync"
	"testing"
)

func TestLog_WritesOneJSONLinePerEntry(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)

	if err := l.Log(Entry{Action: "wl", SourceIP: "203.0.113.5", Result: "ok"}); err != nil {
		t.Fatalf("Log returned error: %v", err)
	}
	if err := l.Log(Entry{Action: "status", SourceIP: "203.0.113.6", Result: "unauthorized"}); err != nil {
		t.Fatalf("Log returned error: %v", err)
	}

	scanner := bufio.NewScanner(&buf)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}

	var e Entry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v", err)
	}
	if e.Action != "wl" || e.SourceIP != "203.0.113.5" || e.Result != "ok" {
		t.Errorf("line 1 decoded to %+v, want action=wl source_ip=203.0.113.5 result=ok", e)
	}
	if e.Time.IsZero() {
		t.Error("Time was not defaulted to now")
	}
}

func TestLog_ConcurrentWritesDoNotInterleave(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_ = l.Log(Entry{Action: "status", SourceIP: "203.0.113.5", Result: "ok"})
		}()
	}
	wg.Wait()

	scanner := bufio.NewScanner(&buf)
	count := 0
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("line %d is not valid JSON (interleaved write?): %v\nline: %s", count, err, scanner.Text())
		}
		count++
	}
	if count != n {
		t.Fatalf("got %d well-formed lines, want %d", count, n)
	}
}
