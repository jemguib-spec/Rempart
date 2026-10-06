//go:build !linux

package secmem

func isNotDumpable() bool { return true }
