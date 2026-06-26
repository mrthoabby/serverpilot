package web

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

const agentDebugLogPath = "/Users/dabadia/dev/own/serverpilot/.cursor/debug-9dbd6e.log"

var agentDebugMu sync.Mutex

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

// #region agent log
func agentDebugLog(hypothesisID, location, message string, data map[string]interface{}) {
	entry := map[string]interface{}{
		"sessionId":    "9dbd6e",
		"hypothesisId": hypothesisID,
		"location":     location,
		"message":      message,
		"data":         data,
		"timestamp":    time.Now().UnixMilli(),
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return
	}
	raw = append(raw, '\n')

	path := os.Getenv("SP_AGENT_DEBUG_LOG")
	if path == "" {
		path = agentDebugLogPath
	}

	agentDebugMu.Lock()
	defer agentDebugMu.Unlock()
	paths := []string{path, "/tmp/debug-9dbd6e.log"}
	for _, p := range paths {
		if p == "" {
			continue
		}
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			continue
		}
		_, _ = f.Write(raw)
		_ = f.Close()
		return
	}
}

// #endregion
