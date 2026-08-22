//go:build !linux && !darwin

package singleton

// Single-instance enforcement needs per-OS process enumeration by executable path, which
// is only implemented for Linux and macOS. Elsewhere it degrades to a no-op: no prior
// instance is ever found, so TakeExclusive returns immediately.
func sameBinaryPIDs(string) ([]int, error) { return nil, nil }
func terminate(int) error                  { return nil }
func forceKill(int) error                  { return nil }
func alivePID(int) bool                    { return false }
