package authority

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/sealed"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/zones"
)

// SecondaryStatus : état d'une zone secondaire, pour l'interface.
type SecondaryStatus struct {
	Name      string    `json:"name"`
	Primary   string    `json:"primary"`
	Serial    uint32    `json:"serial"`
	Records   int       `json:"records"`
	LastOK    time.Time `json:"last_ok"`
	LastError string    `json:"last_error,omitempty"`
	Expired   bool      `json:"expired"`
	Managed   bool      `json:"managed"`
}

type secLoop struct {
	conf   state.SecondaryZone
	cancel context.CancelFunc
	kickCh chan struct{}
	status SecondaryStatus
}

func (a *Authority) kick(zone string) {
	a.secMu.Lock()
	l := a.sec[zone]
	a.secMu.Unlock()
	if l != nil {
		select {
		case l.kickCh <- struct{}{}:
		default:
		}
	}
}

// Secondaries renvoie l'état des zones secondaires.
func (a *Authority) Secondaries() []SecondaryStatus {
	a.secMu.Lock()
	defer a.secMu.Unlock()
	out := []SecondaryStatus{}
	for _, l := range a.sec {
		out = append(out, l.status)
	}
	slices.SortFunc(out, func(x, y SecondaryStatus) int { return strings.Compare(x.Name, y.Name) })
	return out
}

// Reconcile démarre, redémarre ou arrête les zones secondaires selon l'état.
func (a *Authority) Reconcile(ctx context.Context, st state.State) {
	a.secMu.Lock()
	defer a.secMu.Unlock()
	if a.sec == nil {
		a.sec = map[string]*secLoop{}
	}
	want := map[string]state.SecondaryZone{}
	for _, s := range st.Secondaries {
		s.Name = strings.ToLower(dns.Fqdn(s.Name))
		want[s.Name] = s
	}
	for name, l := range a.sec {
		if w, ok := want[name]; !ok || w != l.conf {
			l.cancel()
			delete(a.sec, name)
			if !ok {
				a.Zones.SetSecondary(name, nil)
				_ = os.Remove(a.cachePath(name))
			}
		}
	}
	for name, s := range want {
		if a.sec[name] != nil {
			continue
		}
		lctx, cancel := context.WithCancel(ctx)
		l := &secLoop{conf: s, cancel: cancel, kickCh: make(chan struct{}, 1),
			status: SecondaryStatus{Name: name, Primary: s.Primary, Managed: s.Managed}}
		a.sec[name] = l
		go a.runSecondary(lctx, l)
	}
}

func (a *Authority) setStatus(l *secLoop, f func(*SecondaryStatus)) {
	a.secMu.Lock()
	f(&l.status)
	a.secMu.Unlock()
}

func (a *Authority) runSecondary(ctx context.Context, l *secLoop) {
	name := l.status.Name
	var cur *zones.Zone
	var lastOK time.Time
	// Copie locale : la zone reste servie après un redémarrage, même si le
	// primaire est injoignable, jusqu'à son délai d'expiration.
	if raw, err := sealed.ReadFile(a.KS, a.cachePath(name)); err == nil {
		var c struct {
			At  time.Time `json:"at"`
			RRs []string  `json:"rrs"`
		}
		if json.Unmarshal(raw, &c) == nil {
			var rrs []dns.RR
			for _, s := range c.RRs {
				if rr, err := dns.NewRR(s); err == nil {
					rrs = append(rrs, rr)
				}
			}
			if z, err := zones.FromTransfer(name, rrs); err == nil && time.Since(c.At) < time.Duration(z.SOA().Expire)*time.Second {
				cur, lastOK = z, c.At
				a.Zones.SetSecondary(name, z)
				a.setStatus(l, func(s *SecondaryStatus) { s.Serial, s.LastOK, s.Records = z.Serial(), c.At, len(rrs) })
			}
		}
	}
	wait := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.kickCh:
		case <-time.After(wait):
		}
		next, err := a.refresh(ctx, l, cur)
		if err == nil {
			if next != nil {
				cur = next
			}
			lastOK = time.Now()
			soa := cur.SOA()
			wait = clamp(time.Duration(soa.Refresh)*time.Second, time.Minute, 24*time.Hour)
			a.setStatus(l, func(s *SecondaryStatus) { s.LastOK, s.LastError, s.Expired = lastOK, "", false })
			continue
		}
		a.Log.Warn("zone secondaire non rafraîchie", "zone", name, "primaire", l.conf.Primary, "err", err)
		wait = 2 * time.Minute
		if cur != nil {
			soa := cur.SOA()
			wait = clamp(time.Duration(soa.Retry)*time.Second, 30*time.Second, time.Hour)
			// RFC 1035 : passé le délai d'expiration sans contact, la zone
			// n'est plus servie (des données périmées seraient pires).
			if time.Since(lastOK) > time.Duration(soa.Expire)*time.Second {
				a.Zones.SetSecondary(name, nil)
				cur = nil
				a.setStatus(l, func(s *SecondaryStatus) { s.Expired = true })
			}
		}
		a.setStatus(l, func(s *SecondaryStatus) { s.LastError = err.Error() })
	}
}

func clamp(d, lo, hi time.Duration) time.Duration { return min(max(d, lo), hi) }

// refresh compare le numéro de série et transfère la zone si besoin.
func (a *Authority) refresh(ctx context.Context, l *secLoop, cur *zones.Zone) (*zones.Zone, error) {
	key, ok := a.Prov.Key(l.conf.Key)
	if !ok {
		return nil, errors.New("clé TSIG " + l.conf.Key + " inconnue")
	}
	soa, err := QuerySOA(l.conf.Primary, l.status.Name, key)
	if err != nil {
		return nil, err
	}
	if cur != nil && !zones.SerialNewer(soa.Serial, cur.Serial()) {
		return nil, nil
	}
	tctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	rrs, err := Transfer(tctx, l.conf.Primary, l.status.Name, key)
	if err != nil {
		return nil, err
	}
	z, err := zones.FromTransfer(l.status.Name, rrs)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil { // zone retirée pendant le transfert
		return nil, ctx.Err()
	}
	a.Zones.SetSecondary(l.status.Name, z)
	a.setStatus(l, func(s *SecondaryStatus) { s.Serial, s.Records = z.Serial(), len(rrs) })
	a.Log.Info("zone secondaire transférée", "zone", l.status.Name, "série", z.Serial(), "enregistrements", len(rrs))
	a.saveCache(l.status.Name, rrs)
	return z, nil
}

func (a *Authority) saveCache(name string, rrs []dns.RR) {
	c := struct {
		At  time.Time `json:"at"`
		RRs []string  `json:"rrs"`
	}{At: time.Now().UTC()}
	for _, rr := range rrs[:len(rrs)-1] { // sans le SOA de fin
		c.RRs = append(c.RRs, rr.String())
	}
	raw, _ := json.Marshal(c)
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	if err := sealed.WriteFile(a.KS, a.cachePath(name), raw); err != nil {
		a.Log.Error("copie de la zone secondaire non enregistrée", "zone", name, "err", err)
	}
}

// Reseal réécrit toutes les copies scellées présentes avec la KEK en
// service (rotation), y compris celles d'une zone arrêtée : sinon l'ancienne
// génération resterait utilisée et ne pourrait pas être détruite.
func (a *Authority) Reseal() error {
	if err := a.resealReplay(); err != nil {
		return err
	}
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	files, err := filepath.Glob(filepath.Join(a.DataDir, "secondary-*.sealed"))
	if err != nil {
		return err
	}
	for _, p := range files {
		raw, err := sealed.ReadFile(a.KS, p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := sealed.WriteFile(a.KS, p, raw); err != nil {
			return err
		}
	}
	return nil
}
