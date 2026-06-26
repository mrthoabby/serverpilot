package web

import (
	"sync"
	"time"
)

var lastTerminalWSReject struct {
	mu     sync.Mutex
	status int
	reason string
	at     time.Time
}

func recordTerminalWSReject(status int, reason string) {
	lastTerminalWSReject.mu.Lock()
	defer lastTerminalWSReject.mu.Unlock()
	lastTerminalWSReject.status = status
	lastTerminalWSReject.reason = reason
	lastTerminalWSReject.at = time.Now()
}

func snapshotTerminalWSReject() (status int, reason string, at time.Time) {
	lastTerminalWSReject.mu.Lock()
	defer lastTerminalWSReject.mu.Unlock()
	return lastTerminalWSReject.status, lastTerminalWSReject.reason, lastTerminalWSReject.at
}
