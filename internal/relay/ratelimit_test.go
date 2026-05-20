package relay

import (
	"sync"
	"testing"
	"time"

	"github.com/jsell-rh/lockwire/internal/protocol"
)

func defaultTestConfig() RateLimitConfig {
	return RateLimitConfig{
		ConnectionLimit:    protocol.DefaultConnectionRateLimit,
		ConnectionWindow:   time.Duration(protocol.DefaultConnectionRateWindow) * time.Second,
		RegistrationLimit:  protocol.DefaultRegistrationRateLimit,
		RegistrationWindow: time.Duration(protocol.DefaultRegistrationRateWindow) * time.Second,
		HandshakeLimit:     protocol.DefaultHandshakeRateLimit,
		HandshakeWindow:    time.Duration(protocol.DefaultHandshakeRateWindow) * time.Second,
	}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type rateLimitProbe struct {
	mu             sync.Mutex
	rateLimitCalls []rateLimitCall
	banCalls       []banCall
}

type rateLimitCall struct {
	ip       string
	activity string
}

type banCall struct {
	ip       string
	activity string
	duration string
}

func (p *rateLimitProbe) AcceptError(string, error) {}

func (p *rateLimitProbe) RateLimited(ip, activity string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rateLimitCalls = append(p.rateLimitCalls, rateLimitCall{ip, activity})
}

func (p *rateLimitProbe) BanTriggered(ip, activity, duration string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.banCalls = append(p.banCalls, banCall{ip, activity, duration})
}

func TestRateLimiterAllowsBelowThreshold(t *testing.T) {
	clk := newFakeClock()
	rl := NewRateLimiter(defaultTestConfig(), &rateLimitProbe{}, clk.Now)

	for i := range protocol.DefaultConnectionRateLimit {
		if !rl.Allow("1.2.3.4", EventConnection) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiterDeniesAtThreshold(t *testing.T) {
	clk := newFakeClock()
	probe := &rateLimitProbe{}
	rl := NewRateLimiter(defaultTestConfig(), probe, clk.Now)

	for range protocol.DefaultConnectionRateLimit {
		rl.Allow("1.2.3.4", EventConnection)
	}

	if rl.Allow("1.2.3.4", EventConnection) {
		t.Error("request beyond threshold should be denied")
	}

	probe.mu.Lock()
	defer probe.mu.Unlock()
	if len(probe.rateLimitCalls) != 1 {
		t.Fatalf("probe calls = %d, want 1", len(probe.rateLimitCalls))
	}
	if probe.rateLimitCalls[0].activity != "connection" {
		t.Errorf("activity = %q, want %q", probe.rateLimitCalls[0].activity, "connection")
	}
}

func TestRateLimiterWindowReset(t *testing.T) {
	clk := newFakeClock()
	rl := NewRateLimiter(defaultTestConfig(), &rateLimitProbe{}, clk.Now)

	for range protocol.DefaultConnectionRateLimit {
		rl.Allow("1.2.3.4", EventConnection)
	}

	if rl.Allow("1.2.3.4", EventConnection) {
		t.Error("should be denied before window reset")
	}

	clk.Advance(61 * time.Second)

	if !rl.Allow("1.2.3.4", EventConnection) {
		t.Error("should be allowed after window reset")
	}
}

func TestRateLimiterIndependentIPs(t *testing.T) {
	clk := newFakeClock()
	rl := NewRateLimiter(defaultTestConfig(), &rateLimitProbe{}, clk.Now)

	for range protocol.DefaultConnectionRateLimit {
		rl.Allow("1.2.3.4", EventConnection)
	}

	if rl.Allow("1.2.3.4", EventConnection) {
		t.Error("1.2.3.4 should be denied")
	}

	if !rl.Allow("5.6.7.8", EventConnection) {
		t.Error("5.6.7.8 should be allowed (different IP)")
	}
}

func TestRateLimiterIndependentEventTypes(t *testing.T) {
	clk := newFakeClock()
	rl := NewRateLimiter(defaultTestConfig(), &rateLimitProbe{}, clk.Now)

	for range protocol.DefaultConnectionRateLimit {
		rl.Allow("1.2.3.4", EventConnection)
	}

	if !rl.Allow("1.2.3.4", EventRegistration) {
		t.Error("registration should be allowed even when connections exhausted")
	}
}

func TestRateLimiterRegistrationLimit(t *testing.T) {
	clk := newFakeClock()
	rl := NewRateLimiter(defaultTestConfig(), &rateLimitProbe{}, clk.Now)

	for i := range protocol.DefaultRegistrationRateLimit {
		if !rl.Allow("1.2.3.4", EventRegistration) {
			t.Fatalf("registration %d should be allowed", i+1)
		}
	}

	if rl.Allow("1.2.3.4", EventRegistration) {
		t.Error("registration beyond threshold should be denied")
	}
}

func TestRateLimiterHandshakeLimit(t *testing.T) {
	clk := newFakeClock()
	rl := NewRateLimiter(defaultTestConfig(), &rateLimitProbe{}, clk.Now)

	for i := range protocol.DefaultHandshakeRateLimit {
		if !rl.Allow("1.2.3.4", EventHandshakeFailure) {
			t.Fatalf("handshake %d should be allowed", i+1)
		}
	}

	if rl.Allow("1.2.3.4", EventHandshakeFailure) {
		t.Error("handshake beyond threshold should be denied")
	}
}

func TestBanTriggeredBy3xThreshold(t *testing.T) {
	clk := newFakeClock()
	probe := &rateLimitProbe{}
	rl := NewRateLimiter(defaultTestConfig(), probe, clk.Now)

	limit := protocol.DefaultConnectionRateLimit * protocol.RateLimitBanMultiplier
	for range limit {
		rl.Allow("1.2.3.4", EventConnection)
	}

	if !rl.IsBanned("1.2.3.4") {
		t.Error("IP should be banned after 3x threshold")
	}

	probe.mu.Lock()
	defer probe.mu.Unlock()
	if len(probe.banCalls) != 1 {
		t.Fatalf("ban calls = %d, want 1", len(probe.banCalls))
	}
	if probe.banCalls[0].duration != "1h" {
		t.Errorf("duration = %q, want %q", probe.banCalls[0].duration, "1h")
	}
}

func TestBannedIPDeniedWithoutCounterIncrement(t *testing.T) {
	clk := newFakeClock()
	rl := NewRateLimiter(defaultTestConfig(), &rateLimitProbe{}, clk.Now)

	limit := protocol.DefaultConnectionRateLimit * protocol.RateLimitBanMultiplier
	for range limit {
		rl.Allow("1.2.3.4", EventConnection)
	}

	if !rl.IsBanned("1.2.3.4") {
		t.Fatal("IP should be banned")
	}

	if rl.Allow("1.2.3.4", EventConnection) {
		t.Error("banned IP should be denied")
	}
}

func TestBanExpires(t *testing.T) {
	clk := newFakeClock()
	rl := NewRateLimiter(defaultTestConfig(), &rateLimitProbe{}, clk.Now)

	limit := protocol.DefaultConnectionRateLimit * protocol.RateLimitBanMultiplier
	for range limit {
		rl.Allow("1.2.3.4", EventConnection)
	}

	if !rl.IsBanned("1.2.3.4") {
		t.Fatal("IP should be banned")
	}

	clk.Advance(time.Duration(protocol.BanDurationFirst+1) * time.Second)

	if rl.IsBanned("1.2.3.4") {
		t.Error("ban should have expired after 1 hour")
	}

	if !rl.Allow("1.2.3.4", EventConnection) {
		t.Error("should be allowed after ban expires")
	}
}

func TestProgressiveBanDurations(t *testing.T) {
	clk := newFakeClock()
	probe := &rateLimitProbe{}
	rl := NewRateLimiter(defaultTestConfig(), probe, clk.Now)

	triggerBan := func() {
		limit := protocol.DefaultConnectionRateLimit * protocol.RateLimitBanMultiplier
		for range limit {
			rl.Allow("1.2.3.4", EventConnection)
		}
	}

	// First ban: 1 hour.
	triggerBan()
	if !rl.IsBanned("1.2.3.4") {
		t.Fatal("should be banned (first)")
	}
	clk.Advance(time.Duration(protocol.BanDurationFirst+1) * time.Second)
	if rl.IsBanned("1.2.3.4") {
		t.Fatal("first ban should have expired")
	}

	// Second ban: 24 hours.
	triggerBan()
	if !rl.IsBanned("1.2.3.4") {
		t.Fatal("should be banned (second)")
	}
	clk.Advance(time.Duration(protocol.BanDurationFirst+1) * time.Second)
	if !rl.IsBanned("1.2.3.4") {
		t.Error("second ban should still be active after 1 hour")
	}
	clk.Advance(time.Duration(protocol.BanDurationSecond) * time.Second)
	if rl.IsBanned("1.2.3.4") {
		t.Fatal("second ban should have expired")
	}

	// Third ban: permanent.
	triggerBan()
	if !rl.IsBanned("1.2.3.4") {
		t.Fatal("should be banned (third)")
	}
	clk.Advance(365 * 24 * time.Hour)
	if !rl.IsBanned("1.2.3.4") {
		t.Error("permanent ban should not expire")
	}

	probe.mu.Lock()
	defer probe.mu.Unlock()
	if len(probe.banCalls) != 3 {
		t.Fatalf("ban calls = %d, want 3", len(probe.banCalls))
	}
	if probe.banCalls[0].duration != "1h" {
		t.Errorf("ban 1 duration = %q, want %q", probe.banCalls[0].duration, "1h")
	}
	if probe.banCalls[1].duration != "24h" {
		t.Errorf("ban 2 duration = %q, want %q", probe.banCalls[1].duration, "24h")
	}
	if probe.banCalls[2].duration != "permanent" {
		t.Errorf("ban 3 duration = %q, want %q", probe.banCalls[2].duration, "permanent")
	}
}

func TestBanTriggeredByViolationAccumulation(t *testing.T) {
	clk := newFakeClock()
	probe := &rateLimitProbe{}
	rl := NewRateLimiter(defaultTestConfig(), probe, clk.Now)

	// Exhaust connection limit (violation 1).
	for range protocol.DefaultConnectionRateLimit + 1 {
		rl.Allow("1.2.3.4", EventConnection)
	}

	// Advance past connection window so the counter resets.
	clk.Advance(61 * time.Second)

	// Exhaust registration limit (violation 2).
	for range protocol.DefaultRegistrationRateLimit + 1 {
		rl.Allow("1.2.3.4", EventRegistration)
	}

	if rl.IsBanned("1.2.3.4") {
		t.Error("should not be banned after 2 violations")
	}

	// Advance past registration window.
	clk.Advance(61 * time.Second)

	// Exhaust connection limit again (violation 3).
	for range protocol.DefaultConnectionRateLimit + 1 {
		rl.Allow("1.2.3.4", EventConnection)
	}

	if !rl.IsBanned("1.2.3.4") {
		t.Error("should be banned after 3 violations within 1 hour")
	}
}

func TestViolationWindowExpiry(t *testing.T) {
	clk := newFakeClock()
	rl := NewRateLimiter(defaultTestConfig(), &rateLimitProbe{}, clk.Now)

	// Two violations.
	for range protocol.DefaultConnectionRateLimit + 1 {
		rl.Allow("1.2.3.4", EventConnection)
	}
	clk.Advance(61 * time.Second)
	for range protocol.DefaultRegistrationRateLimit + 1 {
		rl.Allow("1.2.3.4", EventRegistration)
	}

	// Advance past the 1-hour violation window.
	clk.Advance(time.Duration(protocol.RateLimitViolationWindow+1) * time.Second)

	// Third violation outside the 1-hour window should not trigger a ban.
	for range protocol.DefaultConnectionRateLimit + 1 {
		rl.Allow("1.2.3.4", EventConnection)
	}

	if rl.IsBanned("1.2.3.4") {
		t.Error("should not be banned — violations outside 1-hour window")
	}
}

func TestRateLimiterConcurrentAccess(t *testing.T) {
	clk := newFakeClock()
	rl := NewRateLimiter(defaultTestConfig(), &rateLimitProbe{}, clk.Now)

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rl.Allow("1.2.3.4", EventConnection)
			rl.IsBanned("1.2.3.4")
		}()
	}
	wg.Wait()
}
