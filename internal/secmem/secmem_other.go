//go:build !linux

package secmem

func lock(b []byte) {}

func harden() []string { return nil }
