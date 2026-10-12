// ovh.go - API OVHcloud : signature des requêtes (clé d'application, secret,
// clé consommateur), enregistrements TXT de /domain/zone, rafraîchissement.

package acmedns

import (
	"bytes"
	"context"
	"crypto/sha1" // imposé par la signature de l'API OVH ("$1$" = SHA-1)
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type ovh struct {
	base, appKey, appSecret, consumerKey, zone string
	hc                                         *http.Client

	mu     sync.Mutex
	delta  int64 // décalage horloge du serveur OVH - horloge locale
	synced bool
	ids    map[string]int64 // fqdn|valeur → identifiant de l'enregistrement
}

// syncTime : l'API refuse une signature dont l'horodatage s'écarte du sien.
func (o *ovh) syncTime(ctx context.Context) error {
	o.mu.Lock()
	done := o.synced
	o.mu.Unlock()
	if done {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.base+"/auth/time", nil)
	if err != nil {
		return err
	}
	resp, err := o.hc.Do(req)
	if err != nil {
		return fmt.Errorf("API OVH injoignable : %w", err)
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API OVH, heure du serveur : HTTP %d", resp.StatusCode)
	}
	t, err := strconv.ParseInt(string(bytes.TrimSpace(b)), 10, 64)
	if err != nil {
		return fmt.Errorf("API OVH, heure du serveur illisible")
	}
	o.mu.Lock()
	o.delta, o.synced = t-time.Now().Unix(), true
	o.mu.Unlock()
	return nil
}

func (o *ovh) sign(method, u, body, ts string) string {
	h := sha1.Sum([]byte(o.appSecret + "+" + o.consumerKey + "+" + method + "+" + u + "+" + body + "+" + ts))
	return "$1$" + hex.EncodeToString(h[:])
}

func (o *ovh) call(ctx context.Context, method, path string, in, out any) error {
	if err := o.syncTime(ctx); err != nil {
		return err
	}
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	u := o.base + path
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	o.mu.Lock()
	ts := strconv.FormatInt(time.Now().Unix()+o.delta, 10)
	o.mu.Unlock()
	req.Header.Set("X-Ovh-Application", o.appKey)
	req.Header.Set("X-Ovh-Consumer", o.consumerKey)
	req.Header.Set("X-Ovh-Timestamp", ts)
	req.Header.Set("X-Ovh-Signature", o.sign(method, u, string(body), ts))
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := o.hc.Do(req)
	if err != nil {
		return fmt.Errorf("API OVH injoignable : %w", err)
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct{ Message string }
		_ = json.Unmarshal(b, &e)
		hint := ""
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			hint = " (clés ou droits de la clé consommateur à vérifier)"
		}
		return fmt.Errorf("API OVH, %s %s : HTTP %d %s%s", method, path, resp.StatusCode, short(e.Message), hint)
	}
	return decodeJSON(b, out)
}

func (o *ovh) zonePath() string { return "/domain/zone/" + url.PathEscape(o.zone) }

func (o *ovh) refresh(ctx context.Context) error {
	return o.call(ctx, http.MethodPost, o.zonePath()+"/refresh", nil, nil)
}

func (o *ovh) Present(ctx context.Context, fqdn, value string) error {
	sub, err := relName(fqdn, o.zone)
	if err != nil {
		return err
	}
	var rec struct {
		ID int64 `json:"id"`
	}
	in := map[string]any{"fieldType": "TXT", "subDomain": sub, "target": value, "ttl": 60}
	if err := o.call(ctx, http.MethodPost, o.zonePath()+"/record", in, &rec); err != nil {
		return err
	}
	o.mu.Lock()
	o.ids[canon(fqdn)+"|"+value] = rec.ID
	o.mu.Unlock()
	return o.refresh(ctx)
}

func (o *ovh) CleanUp(ctx context.Context, fqdn, value string) error {
	sub, err := relName(fqdn, o.zone)
	if err != nil {
		return err
	}
	key := canon(fqdn) + "|" + value
	o.mu.Lock()
	id, ok := o.ids[key]
	o.mu.Unlock()
	ids := []int64{id}
	if !ok { // après un redémarrage : on retrouve l'enregistrement par sa valeur
		var all []int64
		q := "?fieldType=TXT&subDomain=" + url.QueryEscape(sub)
		if err := o.call(ctx, http.MethodGet, o.zonePath()+"/record"+q, nil, &all); err != nil {
			return err
		}
		ids = ids[:0]
		for _, i := range all {
			var r struct{ Target string }
			if err := o.call(ctx, http.MethodGet, fmt.Sprintf("%s/record/%d", o.zonePath(), i), nil, &r); err == nil && unquote(r.Target) == value {
				ids = append(ids, i)
			}
		}
		if len(ids) == 0 {
			return nil
		}
	}
	for _, i := range ids {
		if err := o.call(ctx, http.MethodDelete, fmt.Sprintf("%s/record/%d", o.zonePath(), i), nil, nil); err != nil {
			return err
		}
	}
	o.mu.Lock()
	delete(o.ids, key)
	o.mu.Unlock()
	return o.refresh(ctx)
}
