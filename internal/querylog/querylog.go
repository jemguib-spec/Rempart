// Package querylog records DNS queries according to the privacy mode:
//
//	none  – only anonymous counters, nothing about domains or clients
//	stats – counters + top blocked domains, still nothing per client
//	full  – complete log, encrypted on disk with one data key per day
//
// Each day's data key is wrapped by the keystore (the HSM when configured).
// When the retention period expires the wrapped key is destroyed first:
// without it the day's log is unreadable, even from a backup or an SSD that
// kept old blocks (crypto-shredding).
//
// Client IPs are pseudonymised with HMAC-SHA256 under a random key that only
// lives in memory and changes every day, so pseudonyms cannot be linked from
// one day to the next and cannot be reversed from disk.
package querylog

import (
	"bufio"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/sealed"
	"github.com/rempart-dns/rempart/internal/secmem"
)

const (
	StatusAllowed = "allowed"
	StatusBlocked = "blocked"
	StatusCached  = "cached"
	StatusLocal   = "local"
	StatusError   = "error"
	StatusRefused = "refused"
	// StatusRewritten : réponse imposée (SafeSearch, YouTube restreint).
	StatusRewritten = "rewritten"

	ModeNone  = "none"
	ModeStats = "stats"
	ModeFull  = "full"

	ringSize = 5000
)

// Entry is one logged query.
type Entry struct {
	Time     time.Time `json:"t"`
	Client   string    `json:"c,omitempty"`
	Name     string    `json:"n"`
	Type     string    `json:"y"`
	Status   string    `json:"s"`
	Rcode    string    `json:"r,omitempty"`
	Upstream string    `json:"u,omitempty"`
	Millis   float64   `json:"ms"`
	Rule     string    `json:"rule,omitempty"`
	Source   string    `json:"src,omitempty"`
	Proto    string    `json:"p,omitempty"`
	Group    string    `json:"g,omitempty"` // groupe d'appareils appliqué
}

type segment struct {
	day  string
	f    *os.File
	w    *bufio.Writer
	aead cipher.AEAD
}

// Logger is safe for concurrent use. Record never blocks the DNS path.
type Logger struct {
	ks    keystore.Keystore
	dir   string
	log   *slog.Logger
	Stats *Stats

	mu        sync.RWMutex
	mode      string
	clientIDs string
	retention int
	ring      []Entry
	ringPos   int
	ringFull  bool
	pseudoKey []byte
	pseudoDay string

	ch       chan Entry
	flushReq chan chan struct{}
	seg      *segment
}

func New(ks keystore.Keystore, dataDir string, log *slog.Logger) (*Logger, error) {
	dir := filepath.Join(dataDir, "querylog")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &Logger{ks: ks, dir: dir, log: log, Stats: NewStats(), mode: ModeNone, clientIDs: "pseudonymize",
		retention: 7, ring: make([]Entry, ringSize), ch: make(chan Entry, 8192), flushReq: make(chan chan struct{})}
	go l.writer()
	return l, nil
}

// Configure applies the privacy settings. Switching to a stricter mode wipes
// what the new mode is not allowed to keep from memory.
func (l *Logger) Configure(mode, clientIDs string, retentionDays int) {
	if mode != ModeStats && mode != ModeFull {
		mode = ModeNone
	}
	if retentionDays < 1 {
		retentionDays = 1
	}
	l.mu.Lock()
	l.mode, l.clientIDs, l.retention = mode, clientIDs, retentionDays
	if mode != ModeFull {
		for i := range l.ring {
			l.ring[i] = Entry{}
		}
		l.ringPos, l.ringFull = 0, false
	}
	l.mu.Unlock()
	l.Stats.forget(mode != ModeFull, mode != ModeFull, mode == ModeNone)
	if mode == ModeNone {
		l.Stats.forgetBlocked()
	}
}

func (l *Logger) Mode() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.mode
}

// ClientID turns an IP into what the privacy settings allow to keep.
func (l *Logger) ClientID(ip netip.Addr) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch l.clientIDs {
	case "clear":
		return ip.String()
	case "truncate":
		bits := 24
		if ip.Is6() && !ip.Is4In6() {
			bits = 48
		}
		p, _ := ip.Unmap().Prefix(bits)
		return p.String()
	}
	day := time.Now().UTC().Format(time.DateOnly)
	if l.pseudoDay != day {
		if l.pseudoKey != nil {
			secmem.Wipe(l.pseudoKey)
		}
		l.pseudoKey = make([]byte, 32)
		_, _ = rand.Read(l.pseudoKey)
		secmem.Lock(l.pseudoKey)
		l.pseudoDay = day
	}
	m := hmac.New(sha256.New, l.pseudoKey)
	m.Write(ip.Unmap().AsSlice())
	return "client-" + hex.EncodeToString(m.Sum(nil)[:5])
}

// Record accounts for one query.
func (l *Logger) Record(e Entry, ip netip.Addr) {
	l.mu.RLock()
	mode := l.mode
	l.mu.RUnlock()
	blockedDomain := ""
	if mode != ModeNone && e.Status == StatusBlocked {
		blockedDomain = strings.TrimSuffix(e.Name, ".")
	}
	if mode != ModeFull {
		l.Stats.add(e, blockedDomain, "", "", mode != ModeNone)
		return
	}
	e.Client = l.ClientID(ip)
	l.Stats.add(e, blockedDomain, strings.TrimSuffix(e.Name, "."), e.Client, true)
	l.mu.Lock()
	l.ring[l.ringPos] = e
	l.ringPos = (l.ringPos + 1) % ringSize
	if l.ringPos == 0 {
		l.ringFull = true
	}
	l.mu.Unlock()
	select {
	case l.ch <- e:
	default: // never slow down DNS because of the disk
	}
}

// Recent returns the latest entries (newest first) matching the filter.
func (l *Logger) Recent(limit int, search, status string) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	n := l.ringPos
	if l.ringFull {
		n = ringSize
	}
	search = strings.ToLower(search)
	out := []Entry{}
	for i := 0; i < n && len(out) < limit; i++ {
		e := l.ring[(l.ringPos-1-i+ringSize)%ringSize]
		if status != "" && e.Status != status {
			continue
		}
		if search != "" && !strings.Contains(e.Name, search) && !strings.Contains(e.Client, search) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (l *Logger) writer() {
	flush := time.NewTicker(2 * time.Second)
	purge := time.NewTicker(time.Hour)
	defer flush.Stop()
	defer purge.Stop()
	l.Purge()
	for {
		select {
		case e, ok := <-l.ch:
			if !ok {
				l.closeSegment()
				return
			}
			if err := l.write(e); err != nil {
				l.log.Error("journal chiffré : écriture impossible", "err", err)
			}
		case done := <-l.flushReq:
			for n := len(l.ch); n > 0; n-- {
				_ = l.write(<-l.ch)
			}
			if l.seg != nil {
				_ = l.seg.w.Flush()
			}
			close(done)
		case <-flush.C:
			if l.seg != nil {
				_ = l.seg.w.Flush()
			}
		case <-purge.C:
			l.Purge()
		}
	}
}

func (l *Logger) closeSegment() {
	if l.seg != nil {
		_ = l.seg.w.Flush()
		_ = l.seg.f.Close()
		l.seg = nil
	}
}

func keyAAD(day string) []byte { return KeyAAD(day) }

// KeyAAD est la donnée associée de la clé chiffrée d'un jour (migration).
func KeyAAD(day string) []byte { return []byte("rempart-querylog:" + day) }

// dayKey returns the data key of a day, creating it if needed.
func (l *Logger) dayKey(day string, create bool) ([]byte, error) {
	path := filepath.Join(l.dir, day+".key")
	if wrapped, err := os.ReadFile(path); err == nil {
		return l.ks.Unwrap(wrapped, keyAAD(day))
	} else if !errors.Is(err, os.ErrNotExist) || !create {
		return nil, err
	}
	dek := sealed.NewDataKey()
	wrapped, err := l.ks.Wrap(dek, keyAAD(day))
	if err != nil {
		return nil, err
	}
	// Écriture atomique : l'inventaire des générations de KEK ne doit jamais
	// lire un fichier à moitié écrit.
	f, err := os.OpenFile(path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(wrapped); err == nil {
		err = f.Sync() // sans fsync, un arrêt brutal pourrait laisser une clé vide après le renommage
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	return dek, os.Rename(path+".tmp", path)
}

func (l *Logger) write(e Entry) error {
	day := e.Time.UTC().Format(time.DateOnly)
	if l.seg == nil || l.seg.day != day {
		l.closeSegment()
		dek, err := l.dayKey(day, true)
		if err != nil {
			return err
		}
		aead, err := sealed.AEAD(dek)
		secmem.Wipe(dek)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(filepath.Join(l.dir, day+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		l.seg = &segment{day: day, f: f, w: bufio.NewWriterSize(f, 64<<10), aead: aead}
	}
	pt, _ := json.Marshal(e)
	nonce := make([]byte, l.seg.aead.NonceSize())
	_, _ = rand.Read(nonce)
	ct := l.seg.aead.Seal(nil, nonce, pt, keyAAD(day))
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(nonce)+len(ct)))
	_, _ = l.seg.w.Write(hdr[:])
	_, _ = l.seg.w.Write(nonce)
	_, err := l.seg.w.Write(ct)
	return err
}

// Days lists the days for which an encrypted log exists.
func (l *Logger) Days() []string {
	files, _ := filepath.Glob(filepath.Join(l.dir, "*.key"))
	days := []string{} // jamais nil : null en JSON fait planter l'interface
	for _, f := range files {
		days = append(days, strings.TrimSuffix(filepath.Base(f), ".key"))
	}
	sort.Sort(sort.Reverse(sort.StringSlice(days)))
	return days
}

// ReadDay decrypts the log of a day (used for search and export).
func (l *Logger) ReadDay(day string, fn func(Entry) bool) error {
	if _, err := time.Parse(time.DateOnly, day); err != nil {
		return errors.New("jour invalide")
	}
	l.Flush()
	dek, err := l.dayKey(day, false)
	if err != nil {
		return errors.New("aucun journal pour ce jour (ou clé détruite)")
	}
	aead, err := sealed.AEAD(dek)
	secmem.Wipe(dek)
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(l.dir, day+".log"))
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n > 1<<20 {
			return errors.New("journal corrompu")
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil // partially written last record
		}
		ns := aead.NonceSize()
		pt, err := aead.Open(nil, buf[:ns], buf[ns:], keyAAD(day))
		if err != nil {
			return errors.New("journal altéré : authentification GCM échouée")
		}
		var e Entry
		if json.Unmarshal(pt, &e) == nil && e.Name != "" && !fn(e) {
			return nil
		}
	}
}

// Purge crypto-shreds the days older than the retention period.
func (l *Logger) Purge() {
	l.mu.RLock()
	keep := l.retention
	l.mu.RUnlock()
	limit := time.Now().UTC().AddDate(0, 0, -keep).Format(time.DateOnly)
	for _, day := range l.Days() {
		if day >= limit {
			continue
		}
		_ = sealed.Shred(filepath.Join(l.dir, day+".key")) // the key first: the log becomes unreadable
		_ = os.Remove(filepath.Join(l.dir, day+".log"))
		l.log.Info("journal expiré détruit (crypto-shredding)", "jour", day)
	}
}

// Flush writes pending entries to disk.
func (l *Logger) Flush() {
	done := make(chan struct{})
	l.flushReq <- done
	<-done
}
