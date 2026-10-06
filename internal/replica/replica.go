// Package replica synchronise des instances de Rempart : une instance
// principale publie sa configuration de filtrage (API, jeton de portée
// « sync »), les répliques la recopient et reçoivent les zones par AXFR
// signé TSIG. Chaque instance garde ce qui lui est propre : compte
// administrateur, annuaires, certificat, keystore, DHCP, journaux.
package replica

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/filter"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/tsig"
)

// Payload : la partie répliquée de l'état.
type Payload struct {
	Settings  state.Settings  `json:"settings"`
	Lists     []state.List    `json:"lists"`
	Rules     []state.Rule    `json:"rules"`
	Groups    []state.Group   `json:"groups"`
	Devices   []state.Device  `json:"devices"`
	Resolvers state.Resolvers `json:"resolvers"`
	RPZ       []state.RPZFeed `json:"rpz"`
	Keys      []state.TSIGKey `json:"tsig_keys"` // clés des flux RPZ et des transferts vers les répliques
	Zones     []string        `json:"zones"`
}

// Export construit la charge publiée par l'instance principale.
func Export(st state.State) Payload {
	p := Payload{Settings: st.Settings, Lists: st.Lists, Rules: st.Rules, Groups: st.Groups, Devices: st.Devices,
		Resolvers: st.Resolvers, RPZ: st.RPZ, Keys: []state.TSIGKey{}, Zones: []string{}}
	for i := range p.Lists {
		p.Lists[i].Count, p.Lists[i].LastError = 0, ""
	}
	need := map[string]bool{tsig.CanonicalName(st.Replication.Key): st.Replication.Key != ""}
	for _, f := range st.RPZ {
		if f.Key != "" {
			need[tsig.CanonicalName(f.Key)] = true
		}
	}
	for _, k := range st.TSIGKeys {
		if need[k.Name] {
			k.Managed = false
			p.Keys = append(p.Keys, k)
		}
	}
	for _, z := range st.Zones {
		p.Zones = append(p.Zones, strings.ToLower(dns.Fqdn(z.Name)))
	}
	return p
}

// ETag : empreinte de la charge (évite de réappliquer une configuration
// inchangée).
func ETag(p Payload) string {
	raw, _ := json.Marshal(p)
	h := sha256.Sum256(raw)
	return `"` + hex.EncodeToString(h[:16]) + `"`
}

// Apply recopie la charge dans l'état d'une réplique. Seules les listes
// https:// sont reprises : une liste désignée par un chemin local n'a de
// sens que sur l'instance principale, et une réplique ne lit pas un fichier
// de son disque sur l'ordre d'un autre serveur.
func Apply(s *state.State, p Payload, replKey string) {
	lists := make([]state.List, 0, len(p.Lists))
	for _, l := range p.Lists {
		if strings.HasPrefix(l.URL, "https://") {
			lists = append(lists, l)
		}
	}
	// Chaque instance garde ses propres choix de journalisation.
	set := p.Settings
	set.LogMode, set.RetentionDays, set.ClientIDs, set.Suggestions = s.Settings.LogMode, s.Settings.RetentionDays, s.Settings.ClientIDs, s.Settings.Suggestions
	s.Settings, s.Lists, s.Rules, s.Groups, s.Devices, s.Resolvers, s.RPZ = set, lists, p.Rules, p.Groups, p.Devices, p.Resolvers, p.RPZ
	var keys []state.TSIGKey
	local := map[string]bool{}
	for _, k := range s.TSIGKeys {
		if !k.Managed {
			keys = append(keys, k)
			local[k.Name] = true
		}
	}
	for _, k := range p.Keys {
		// Une clé locale homonyme n'est jamais remplacée par celle reçue.
		if local[tsig.CanonicalName(k.Name)] {
			continue
		}
		k.Name = tsig.CanonicalName(k.Name)
		k.Managed = true
		keys = append(keys, k)
	}
	s.TSIGKeys = keys
	var sec []state.SecondaryZone
	for _, z := range s.Secondaries {
		if !z.Managed {
			sec = append(sec, z)
		}
	}
	if replKey != "" && s.Replication.PrimaryDNS != "" {
		for _, z := range p.Zones {
			if _, ok := filter.NormalizeDomain(z); !ok {
				continue // nom de zone invalide reçu : ignoré
			}
			sec = append(sec, state.SecondaryZone{Name: z, Primary: s.Replication.PrimaryDNS, Key: replKey, Managed: true})
		}
	}
	s.Secondaries = sec
}

// Status : état de la synchronisation d'une réplique.
type Status struct {
	LastSync  time.Time `json:"last_sync"`
	LastCheck time.Time `json:"last_check"`
	LastError string    `json:"last_error,omitempty"`
	ETag      string    `json:"etag,omitempty"`
	// LastContact : dernier échange réussi avec l'autre instance (bascule).
	LastContact time.Time `json:"last_contact"`
	Peer        *RoleInfo `json:"peer,omitempty"`
}

// syncInterval : période de synchronisation et de surveillance.
var syncInterval = 30 * time.Second

// Client : boucle de synchronisation d'une réplique.
type Client struct {
	Store *state.Store
	Log   *slog.Logger
	// Applied est appelé après l'application d'une nouvelle configuration.
	Applied func(changes int)
	// Event inscrit une bascule dans le journal d'audit.
	Event func(action, detail string)

	mu     sync.Mutex
	status Status
	cancel context.CancelFunc
	conf   string
}

// Status renvoie l'état de la synchronisation.
func (c *Client) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// Reconcile démarre ou arrête la boucle selon le rôle de l'instance.
func (c *Client) Reconcile(ctx context.Context, st state.State) {
	r := st.Replication
	conf := ""
	switch {
	case r.Role == "replica":
		conf = fmt.Sprintf("replica|%s|%s|%s|%s|%v|%d|%v", r.PrimaryURL, r.PrimaryDNS, tokenFP(r.Token), r.CABundle, r.Failover, r.FailoverMinutes, r.Preferred)
	case r.Role == "primary" && r.Failover && r.PrimaryURL != "":
		conf = fmt.Sprintf("watch|%s|%s|%s", r.PrimaryURL, tokenFP(r.Token), r.CABundle)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if conf == c.conf {
		return
	}
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	c.conf = conf
	c.status = Status{}
	if conf == "" {
		return
	}
	lctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	if r.Role == "primary" {
		go c.watch(lctx, r)
		return
	}
	go c.run(lctx, r)
}

func tokenFP(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:8])
}

// HTTPClient : TLS vérifié, AC de la PKI interne ajoutée aux racines.
func HTTPClient(caPEM string) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if caPEM != "" && !roots.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("AC de l'instance principale : PEM invalide")
	}
	// Aucune redirection : le jeton de synchronisation ne suit pas une
	// réponse qui l'enverrait ailleurs (ou en clair sur le même hôte).
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func (c *Client) run(ctx context.Context, r state.Replication) {
	started := time.Now()
	for {
		peer, err := c.syncOnce(ctx, r)
		now := time.Now().UTC()
		c.mu.Lock()
		c.status.LastCheck = now
		if err != nil {
			c.status.LastError = err.Error()
		} else {
			c.status.LastError, c.status.LastContact, c.status.Peer = "", now, peer
		}
		last := c.status.LastContact
		c.mu.Unlock()
		if err != nil {
			c.Log.Warn("réplication : synchronisation en échec", "err", err)
		}
		if r.Failover {
			if last.IsZero() {
				last = started
			}
			cur := c.Store.Get().Replication
			switch {
			case err != nil && time.Since(last) >= failoverDelay(r):
				// Instance principale injoignable : prise du rôle principal.
				if c.promote(cur.Epoch, fmt.Sprintf("instance principale injoignable depuis %s", time.Since(last).Round(time.Second))) == nil {
					return
				}
			case err == nil && cur.Preferred && peer != nil && peer.Acting:
				// Retour de l'instance préférée : configuration de la panne
				// recopiée, elle reprend le rôle principal.
				if c.promote(peer.Epoch, "retour de l'instance préférée") == nil {
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(syncInterval):
		}
	}
}

func (c *Client) syncOnce(ctx context.Context, r state.Replication) (*RoleInfo, error) {
	err := c.sync(ctx, r)
	if err != nil {
		return nil, err
	}
	if !r.Failover {
		return nil, nil
	}
	peer, err := peerRole(ctx, r)
	if err != nil {
		return nil, err
	}
	return &peer, nil
}

func (c *Client) sync(ctx context.Context, r state.Replication) error {
	u, err := url.Parse(r.PrimaryURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("adresse de l'instance principale : https://hôte:port attendu")
	}
	hc, err := HTTPClient(r.CABundle)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(r.PrimaryURL, "/")+"/api/sync", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.Token)
	c.mu.Lock()
	if c.status.ETag != "" {
		req.Header.Set("If-None-Match", c.status.ETag)
	}
	c.mu.Unlock()
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error string }
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
		return fmt.Errorf("instance principale : HTTP %d %s", resp.StatusCode, e.Error)
	}
	var out struct {
		Payload Payload `json:"payload"`
		Key     string  `json:"replication_key"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&out); err != nil {
		return fmt.Errorf("réponse illisible : %w", err)
	}
	etag := resp.Header.Get("ETag")
	if err := c.Store.Update(func(s *state.State) error {
		Apply(s, out.Payload, out.Key)
		// Bascule : la clé de réplication servira aux transferts si cette
		// instance devient principale.
		if s.Replication.Failover && out.Key != "" {
			s.Replication.Key = tsig.CanonicalName(out.Key)
		}
		return nil
	}); err != nil {
		return err
	}
	c.mu.Lock()
	c.status.ETag, c.status.LastSync = etag, time.Now().UTC()
	c.mu.Unlock()
	if c.Applied != nil {
		c.Applied(len(out.Payload.Lists) + len(out.Payload.Groups) + len(out.Payload.Rules))
	}
	return nil
}
