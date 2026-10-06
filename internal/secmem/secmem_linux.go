//go:build linux

package secmem

import (
	"syscall"
)

const prSetDumpable = 4

func lock(b []byte) {
	if len(b) > 0 {
		_ = syscall.Mlock(b)
	}
}

func harden() []string {
	var applied []string
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err == nil {
		applied = append(applied, "core dumps désactivés")
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); errno == 0 {
		applied = append(applied, "processus non-dumpable (ptrace bloqué)")
	}
	return applied
}
