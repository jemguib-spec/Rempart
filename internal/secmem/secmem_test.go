package secmem

import (
	"runtime"
	"testing"
)

func TestWipe(t *testing.T) {
	b := []byte("phrase de passe")
	Wipe(b)
	for i, c := range b {
		if c != 0 {
			t.Fatalf("octet %d non effacé", i)
		}
	}
	Wipe(nil)
	Wipe([]byte{})
}

func TestWipeSubslice(t *testing.T) {
	b := []byte("0123456789")
	Wipe(b[2:5])
	if string(b[:2]) != "01" || string(b[5:]) != "56789" || b[2]|b[3]|b[4] != 0 {
		t.Fatalf("%q", b)
	}
}

func TestLockNoPanic(t *testing.T) {
	Lock(nil)
	Lock([]byte{})
	Lock(make([]byte, 64))
}

func TestHarden(t *testing.T) {
	applied := Harden()
	if runtime.GOOS != "linux" {
		if len(applied) != 0 {
			t.Fatal("durcissement annoncé hors Linux")
		}
		return
	}
	if len(applied) == 0 {
		t.Fatal("aucun durcissement appliqué sous Linux")
	}
	if !isNotDumpable() {
		t.Fatal("le processus est encore dumpable")
	}
}
