//go:build linux

package secmem

import "syscall"

func isNotDumpable() bool {
	const prGetDumpable = 3
	r, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0)
	return errno == 0 && r == 0
}
