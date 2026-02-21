package metrics

import "testing"

func TestRegister_NoPanic(t *testing.T) {
	// Verify Register can be called multiple times without panicking.
	// The sync.Once inside Register() should ensure idempotency.
	Register()
	Register() // second call should be a no-op
}
