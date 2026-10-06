// Package secmem holds small helpers to keep secrets out of swap, core dumps
// and memory once they are no longer needed.
package secmem

// Wipe overwrites a byte slice with zeros.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Lock tries to pin the slice in RAM so that it is never written to swap.
// It is best effort: failures (missing CAP_IPC_LOCK, low RLIMIT_MEMLOCK,
// non-Linux OS) are ignored.
func Lock(b []byte) { lock(b) }

// Harden disables core dumps and ptrace attachment for this process on
// Linux, so that a crash or a local attacker cannot dump keys from memory.
// It returns a human readable list of what was applied.
func Harden() []string { return harden() }
