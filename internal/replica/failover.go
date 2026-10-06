// failover.go - bascule automatique entre deux instances.
//
// La réplique désignée prend le rôle principal (« par intérim ») quand
// l'instance principale reste injoignable FailoverMinutes. Chaque prise du
// rôle principal incrémente une époque. Une instance principale qui voit
// l'autre principale avec une époque plus grande (ou égale, si elle-même
// n'est que par intérim) redevient réplique et recopie la configuration :
// les modifications faites pendant la panne sont conservées. L'instance
// préférée, revenue en réplique, reprend ensuite le rôle principal après
// une synchronisation réussie (retour automatique).
package replica

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/tsig"
)

// DefaultFailoverMinutes : délai sans contact avant la bascule.
const DefaultFailoverMinutes = 5

// RoleInfo : rôle publié aux autres instances (GET /api/sync/role).
type RoleInfo struct {
	Role   string `json:"role"`
	Epoch  uint64 `json:"epoch"`
	Acting bool   `json:"acting"`
}

func failoverDelay(r state.Replication) time.Duration {
	m := r.FailoverMinutes
	if m <= 0 {
		m = DefaultFailoverMinutes
	}
	return time.Duration(m) * failoverUnit
}

// failoverUnit : une minute (raccourcie dans les tests).
var failoverUnit = time.Minute

// hostOf : adresse IP d'un « IP » ou « IP:port ».
func hostOf(s string) string {
	h := s
	if hh, _, err := net.SplitHostPort(s); err == nil {
		h = hh
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String()
	}
	return ""
}

// promote : cette réplique prend le rôle principal par intérim.
func (c *Client) promote(peerEpoch uint64, why string) error {
	var detail string
	err := c.Store.Update(func(s *state.State) error {
		r := &s.Replication
		if r.Role != "replica" || !r.Failover {
			return errors.New("bascule non configurée")
		}
		if len(r.Replicas) == 0 {
			if h := hostOf(r.PrimaryDNS); h != "" {
				r.Replicas = []string{h}
			}
		}
		if r.Key == "" {
			return errors.New("aucune clé TSIG de réplication connue : bascule impossible")
		}
		r.Role, r.Epoch = "primary", max(r.Epoch, peerEpoch)+1
		r.Acting = !r.Preferred
		// La clé de réplication reçue devient locale : elle sert désormais
		// aux transferts vers l'autre instance.
		for i := range s.TSIGKeys {
			if s.TSIGKeys[i].Name == tsig.CanonicalName(r.Key) {
				s.TSIGKeys[i].Managed = false
			}
		}
		detail = fmt.Sprintf("époque %d, %s", r.Epoch, why)
		return nil
	})
	if err == nil {
		c.Log.Warn("réplication : cette instance devient principale", "motif", why)
		what := "instance principale"
		if c.Store.Get().Replication.Acting {
			what += " par intérim"
		}
		c.event("réplication.bascule", what+" : "+detail)
	}
	return err
}

// stepDown : une autre instance tient le rôle principal avec une époque
// plus grande ; celle-ci redevient réplique.
func (c *Client) stepDown(peer RoleInfo) error {
	err := c.Store.Update(func(s *state.State) error {
		r := &s.Replication
		if r.Role != "primary" {
			return errors.New("déjà réplique")
		}
		r.Role, r.Epoch, r.Acting = "replica", peer.Epoch, false
		return nil
	})
	if err == nil {
		c.Log.Warn("réplication : l'autre instance est principale, celle-ci redevient réplique", "époque", peer.Epoch)
		c.event("réplication.retour", fmt.Sprintf("redevient réplique (époque %d de l'autre instance)", peer.Epoch))
	}
	return err
}

func (c *Client) event(action, detail string) {
	if c.Event != nil {
		c.Event(action, detail)
	}
}

// peerRole lit le rôle de l'autre instance.
func peerRole(ctx context.Context, r state.Replication) (RoleInfo, error) {
	var out RoleInfo
	hc, err := HTTPClient(r.CABundle)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(r.PrimaryURL, "/")+"/api/sync/role", nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("Authorization", "Bearer "+r.Token)
	resp, err := hc.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("autre instance : HTTP %d", resp.StatusCode)
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out)
	return out, err
}

// shouldYield : une instance principale doit-elle céder devant peer ?
func shouldYield(me state.Replication, peer RoleInfo) bool {
	if peer.Role != "primary" {
		return false
	}
	if peer.Epoch != me.Epoch {
		return peer.Epoch > me.Epoch
	}
	// Même époque (prises simultanées) : l'intérim cède à la préférée.
	return me.Acting && !peer.Acting
}

// watch : boucle d'une instance principale avec bascule : surveille
// l'autre instance et cède si elle a pris le rôle principal après elle.
func (c *Client) watch(ctx context.Context, r state.Replication) {
	for {
		if peer, err := peerRole(ctx, r); err == nil {
			c.mu.Lock()
			c.status.LastCheck = time.Now().UTC()
			c.status.LastError = ""
			c.status.Peer = &peer
			c.mu.Unlock()
			cur := c.Store.Get().Replication
			if shouldYield(cur, peer) {
				_ = c.stepDown(peer)
				return // Reconcile relance la boucle de réplique
			}
		} else {
			c.mu.Lock()
			c.status.LastCheck, c.status.LastError, c.status.Peer = time.Now().UTC(), "autre instance injoignable : "+err.Error(), nil
			c.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(syncInterval):
		}
	}
}
