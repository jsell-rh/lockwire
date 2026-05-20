package relay

import (
	"sync"
	"time"

	"github.com/jsell-rh/lockwire/internal/protocol"
)

type EventType int

const (
	EventConnection      EventType = iota
	EventRegistration
	EventHandshakeFailure
)

func eventName(e EventType) string {
	switch e {
	case EventConnection:
		return "connection"
	case EventRegistration:
		return "registration"
	case EventHandshakeFailure:
		return "handshake"
	default:
		return "unknown"
	}
}

type RateLimitConfig struct {
	ConnectionLimit    int
	ConnectionWindow   time.Duration
	RegistrationLimit  int
	RegistrationWindow time.Duration
	HandshakeLimit     int
	HandshakeWindow    time.Duration
}

func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		ConnectionLimit:    protocol.DefaultConnectionRateLimit,
		ConnectionWindow:   time.Duration(protocol.DefaultConnectionRateWindow) * time.Second,
		RegistrationLimit:  protocol.DefaultRegistrationRateLimit,
		RegistrationWindow: time.Duration(protocol.DefaultRegistrationRateWindow) * time.Second,
		HandshakeLimit:     protocol.DefaultHandshakeRateLimit,
		HandshakeWindow:    time.Duration(protocol.DefaultHandshakeRateWindow) * time.Second,
	}
}

func (c RateLimitConfig) limitFor(e EventType) int {
	switch e {
	case EventConnection:
		return c.ConnectionLimit
	case EventRegistration:
		return c.RegistrationLimit
	case EventHandshakeFailure:
		return c.HandshakeLimit
	default:
		return 0
	}
}

func (c RateLimitConfig) windowFor(e EventType) time.Duration {
	switch e {
	case EventConnection:
		return c.ConnectionWindow
	case EventRegistration:
		return c.RegistrationWindow
	case EventHandshakeFailure:
		return c.HandshakeWindow
	default:
		return time.Minute
	}
}

type windowCounter struct {
	count       int
	windowStart time.Time
}

type ipState struct {
	counters   map[EventType]*windowCounter
	violations []time.Time
	banCount   int
	bannedAt   time.Time
	banExpiry  time.Time
	permanent  bool
}

type RateLimiter struct {
	mu     sync.Mutex
	config RateLimitConfig
	ips    map[string]*ipState
	clock  func() time.Time
	probe  Probe
}

func NewRateLimiter(config RateLimitConfig, probe Probe, clock func() time.Time) *RateLimiter {
	return &RateLimiter{
		config: config,
		ips:    make(map[string]*ipState),
		clock:  clock,
		probe:  probe,
	}
}

func (rl *RateLimiter) getOrCreate(ip string) *ipState {
	state, ok := rl.ips[ip]
	if !ok {
		state = &ipState{
			counters: make(map[EventType]*windowCounter),
		}
		rl.ips[ip] = state
	}
	return state
}

func (rl *RateLimiter) IsBanned(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	state, ok := rl.ips[ip]
	if !ok {
		return false
	}
	return rl.isBannedLocked(state)
}

func (rl *RateLimiter) isBannedLocked(state *ipState) bool {
	if state.permanent {
		return true
	}
	if state.banExpiry.IsZero() {
		return false
	}
	return rl.clock().Before(state.banExpiry)
}

func (rl *RateLimiter) Allow(ip string, event EventType) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	state := rl.getOrCreate(ip)

	if rl.isBannedLocked(state) {
		return false
	}

	now := rl.clock()
	limit := rl.config.limitFor(event)
	window := rl.config.windowFor(event)

	counter, ok := state.counters[event]
	if !ok {
		counter = &windowCounter{windowStart: now}
		state.counters[event] = counter
	}

	if now.Sub(counter.windowStart) >= window {
		counter.count = 0
		counter.windowStart = now
	}

	counter.count++

	banThreshold := limit * protocol.RateLimitBanMultiplier
	if counter.count >= banThreshold {
		rl.ban(ip, state, event)
		return false
	}

	if counter.count > limit {
		if counter.count == limit+1 {
			rl.recordViolation(ip, state, event, now)
		}
		rl.probe.RateLimited(ip, eventName(event))
		return false
	}

	return true
}

func (rl *RateLimiter) recordViolation(ip string, state *ipState, event EventType, now time.Time) {
	violationWindow := time.Duration(protocol.RateLimitViolationWindow) * time.Second
	var recent []time.Time
	for _, t := range state.violations {
		if now.Sub(t) < violationWindow {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	state.violations = recent

	if len(recent) >= protocol.RateLimitViolationBanCount {
		rl.ban(ip, state, event)
	}
}

func (rl *RateLimiter) ban(ip string, state *ipState, event EventType) {
	state.banCount++
	state.bannedAt = rl.clock()

	var durationLabel string
	switch state.banCount {
	case 1:
		state.banExpiry = state.bannedAt.Add(time.Duration(protocol.BanDurationFirst) * time.Second)
		durationLabel = "1h"
	case 2:
		state.banExpiry = state.bannedAt.Add(time.Duration(protocol.BanDurationSecond) * time.Second)
		durationLabel = "24h"
	default:
		state.permanent = true
		durationLabel = "permanent"
	}

	rl.probe.BanTriggered(ip, eventName(event), durationLabel)
}
