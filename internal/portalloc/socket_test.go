package portalloc

import "testing"

func TestDispatchSocketRequestInvalidOp(t *testing.T) {
	resp := dispatchSocketRequest(socketRequest{Op: "nope"})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected error for unknown op, got %#v", resp)
	}
}

func TestDispatchSocketRequestInvalidRange(t *testing.T) {
	resp := dispatchSocketRequest(socketRequest{Op: "allocate", Min: 5000, Max: 1000})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected range error, got %#v", resp)
	}
}
