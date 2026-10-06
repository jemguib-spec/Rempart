// Package audit keeps a tamper-evident trail of administrator actions.
//
// Each event contains the hash of the previous one (hash chain) and is signed
// by a keystore key (inside the HSM when configured). The latest sequence
// number and hash are also kept in a sealed "head" file, so deleting the end
// of the log is detected as well as modifying or removing an entry.
package audit

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/sealed"
)

const KeyLabel = "rempart-audit"

type Event struct {
	Seq    uint64    `json:"seq"`
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Detail string    `json:"detail,omitempty"`
	Prev   string    `json:"prev"`
	Hash   string    `json:"hash"`
	Sig    string    `json:"sig"`
}

type head struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

type Log struct {
	// OnAdd est appelé après chaque ajout (verrou tenu) ; il ne doit pas
	// bloquer. Sert à réveiller la copie vers le syslog.
	OnAdd func(Event)

	mu     sync.Mutex
	ks     keystore.Keystore
	signer crypto.Signer
	path   string
	head   head
}

func Open(ks keystore.Keystore, dataDir string) (*Log, error) {
	signer, err := ks.Signer(KeyLabel, keystore.ECDSAP256, true)
	if err != nil {
		return nil, err
	}
	l := &Log{ks: ks, signer: signer, path: filepath.Join(dataDir, "audit.jsonl")}
	if raw, err := sealed.ReadFile(ks, l.headPath()); err == nil {
		_ = json.Unmarshal(raw, &l.head)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("tête du journal d'audit altérée: %w", err)
	}
	return l, nil
}

func (l *Log) headPath() string { return l.path + ".head" }

func digest(e *Event) []byte {
	payload, _ := json.Marshal(struct {
		Seq    uint64    `json:"seq"`
		Time   time.Time `json:"time"`
		Actor  string    `json:"actor"`
		Action string    `json:"action"`
		Detail string    `json:"detail"`
		Prev   string    `json:"prev"`
	}{e.Seq, e.Time, e.Actor, e.Action, e.Detail, e.Prev})
	h := sha256.Sum256(payload)
	return h[:]
}

// Add appends a signed event.
func (l *Log) Add(actor, action, detail string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Event{Seq: l.head.Seq + 1, Time: time.Now().UTC().Truncate(time.Millisecond), Actor: actor, Action: action, Detail: detail, Prev: l.head.Hash}
	d := digest(&e)
	e.Hash = hex.EncodeToString(d)
	var sig []byte
	var err error
	if _, ok := l.signer.Public().(ed25519.PublicKey); ok {
		sig, err = l.signer.Sign(rand.Reader, d, crypto.Hash(0))
	} else {
		sig, err = l.signer.Sign(rand.Reader, d, crypto.SHA256)
	}
	if err != nil {
		return err
	}
	e.Sig = base64.StdEncoding.EncodeToString(sig)
	line, _ := json.Marshal(e)
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	if err == nil {
		err = f.Sync()
	}
	f.Close()
	if err != nil {
		return err
	}
	l.head = head{Seq: e.Seq, Hash: e.Hash}
	raw, _ := json.Marshal(l.head)
	err = sealed.WriteFile(l.ks, l.headPath(), raw)
	if l.OnAdd != nil {
		l.OnAdd(e)
	}
	return err
}

// Seq renvoie le numéro du dernier événement.
func (l *Log) Seq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head.Seq
}

// ReadFrom lit au plus max événements à partir de l'octet offset du journal
// et renvoie la position qui suit le dernier événement complet lu.
func (l *Log) ReadFrom(offset int64, max int) ([]Event, int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, offset, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, 0); err != nil {
		return nil, offset, err
	}
	r := bufio.NewReader(f)
	var out []Event
	for len(out) < max {
		line, err := r.ReadBytes('\n')
		if err != nil {
			break // fin de fichier, ou ligne en cours d'écriture
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return out, offset, fmt.Errorf("journal d'audit illisible à l'octet %d", offset)
		}
		out = append(out, e)
		offset += int64(len(line))
	}
	return out, offset, nil
}

// Report is the result of a full verification.
type Report struct {
	OK      bool   `json:"ok"`
	Count   uint64 `json:"count"`
	Problem string `json:"problem,omitempty"`
	KeyFP   string `json:"key_fingerprint"`
}

// Verify checks hashes, chaining, signatures and the sealed head.
func (l *Log) Verify() Report {
	l.mu.Lock()
	defer l.mu.Unlock()
	rep := Report{KeyFP: keystore.Fingerprint(l.signer.Public())}
	fail := func(f string, a ...any) Report { rep.Problem = fmt.Sprintf(f, a...); return rep }
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		if l.head.Seq != 0 {
			return fail("journal d'audit supprimé (%d événements attendus)", l.head.Seq)
		}
		rep.OK = true
		return rep
	} else if err != nil {
		return fail("%v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	prev := ""
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return fail("ligne %d illisible", rep.Count+1)
		}
		if e.Seq != rep.Count+1 {
			return fail("séquence rompue à l'événement %d (attendu %d)", e.Seq, rep.Count+1)
		}
		if e.Prev != prev {
			return fail("chaînage rompu à l'événement %d", e.Seq)
		}
		d := digest(&e)
		if hex.EncodeToString(d) != e.Hash {
			return fail("événement %d modifié (empreinte invalide)", e.Seq)
		}
		sig, _ := base64.StdEncoding.DecodeString(e.Sig)
		if !verifySig(l.signer.Public(), d, sig) {
			return fail("signature invalide sur l'événement %d", e.Seq)
		}
		prev = e.Hash
		rep.Count++
	}
	if rep.Count != l.head.Seq || prev != l.head.Hash {
		return fail("fin du journal tronquée ou remplacée (%d événements présents, %d attendus)", rep.Count, l.head.Seq)
	}
	rep.OK = true
	return rep
}

func verifySig(pub crypto.PublicKey, d, sig []byte) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, d, sig)
	case ed25519.PublicKey:
		return ed25519.Verify(k, d, sig)
	}
	return false
}

// Last returns up to n events, newest first.
func (l *Log) Last(n int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if err != nil {
		return []Event{}
	}
	defer f.Close()
	var all []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			all = append(all, e)
		}
	}
	out := []Event{}
	for i := len(all) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, all[i])
	}
	return out
}
