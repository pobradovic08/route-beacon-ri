package history

import "crypto/sha256"

// ComputeEventID computes the SHA256 hash of the BMP message bytes.
// The hash is computed on the raw BMP bytes, NOT the OpenBMP wrapper.
// Returns a 32-byte digest suitable for BYTEA storage.
func ComputeEventID(bmpBytes []byte) []byte {
	h := sha256.Sum256(bmpBytes)
	return h[:]
}
