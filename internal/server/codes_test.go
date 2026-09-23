package server

import (
	"sync"
	"testing"
	"time"
)

// storeWithClock returns a code store whose clock the test moves by hand.
func storeWithClock() (*codeStore, *time.Time) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	cs := newCodeStore()
	cs.now = func() time.Time { return now }
	return cs, &now
}

func TestCodeStoreRedeemsOnce(t *testing.T) {
	cs, _ := storeWithClock()
	code := cs.issue(&authCode{clientID: "web-app", subject: "alice"})
	grant, ok := cs.redeem(code)
	if !ok || grant.clientID != "web-app" || grant.subject != "alice" {
		t.Fatalf("first redeem = %+v, %v", grant, ok)
	}
	if _, ok := cs.redeem(code); ok {
		t.Error("second redeem succeeded, want codes to be single use")
	}
}

func TestCodeStoreCodesExpireAfterLifetime(t *testing.T) {
	cs, now := storeWithClock()
	onTime := cs.issue(&authCode{clientID: "web-app"})
	late := cs.issue(&authCode{clientID: "web-app"})
	*now = now.Add(codeLifetime)
	if _, ok := cs.redeem(onTime); !ok {
		t.Error("code rejected at exactly its lifetime, want still redeemable")
	}
	*now = now.Add(time.Second)
	if _, ok := cs.redeem(late); ok {
		t.Error("code redeemed after its lifetime")
	}
}

func TestCodeStoreIssueSweepsExpiredCodes(t *testing.T) {
	cs, now := storeWithClock()
	cs.issue(&authCode{clientID: "stale"})
	*now = now.Add(codeLifetime + time.Second)
	fresh := cs.issue(&authCode{clientID: "fresh"})
	if len(cs.codes) != 1 {
		t.Errorf("store holds %d codes, want only the fresh one", len(cs.codes))
	}
	if _, ok := cs.codes[fresh]; !ok {
		t.Error("fresh code missing after the sweep")
	}
}

func TestCodeStoreCodesAreDistinct(t *testing.T) {
	cs, _ := storeWithClock()
	a, b := cs.issue(&authCode{}), cs.issue(&authCode{})
	if a == "" || a == b {
		t.Errorf("codes %q and %q, want distinct non-empty codes", a, b)
	}
}

// The store is shared by every request, so browsers and backends hit it
// concurrently; run with -race to catch unguarded access.
func TestCodeStoreConcurrentUse(t *testing.T) {
	cs := newCodeStore()
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code := cs.issue(&authCode{clientID: "web-app"})
			if _, ok := cs.redeem(code); !ok {
				t.Error("freshly issued code not redeemable")
			}
		}()
	}
	wg.Wait()
}
