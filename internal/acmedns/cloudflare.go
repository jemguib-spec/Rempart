// cloudflare.go - API Cloudflare v4 : jeton porteur limité à la zone,
// enregistrements TXT de /zones/{id}/dns_records.

package acmedns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type cloudflare struct {
	base, token, zone string
	hc                *http.Client

	mu     sync.Mutex
	zoneID string
	ids    map[string]string // fqdn|valeur → identifiant de l'enregistrement
}

func (c *cloudflare) call(ctx context.Context, method, path string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("API Cloudflare injoignable : %w", err)
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	var env struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
	}
	_ = json.Unmarshal(b, &env)
	if resp.StatusCode >= 300 || !env.Success {
		msgs := []string{}
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		hint := ""
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			hint = " (jeton ou droits Zone:Read et DNS:Edit à vérifier)"
		}
		return fmt.Errorf("API Cloudflare, %s %s : HTTP %d %s%s", method, strings.SplitN(path, "?", 2)[0], resp.StatusCode, short(strings.Join(msgs, " ; ")), hint)
	}
	return decodeJSON(env.Result, out)
}

func (c *cloudflare) zoneIDFor(ctx context.Context) (string, error) {
	c.mu.Lock()
	id := c.zoneID
	c.mu.Unlock()
	if id != "" {
		return id, nil
	}
	var zs []struct{ ID, Name string }
	if err := c.call(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(c.zone), nil, &zs); err != nil {
		return "", err
	}
	for _, z := range zs {
		if canon(z.Name) == c.zone && z.ID != "" {
			c.mu.Lock()
			c.zoneID = z.ID
			c.mu.Unlock()
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("Cloudflare : zone %s introuvable, ou jeton sans le droit Zone:Read sur elle", c.zone)
}

var cfIDRe = func(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func (c *cloudflare) Present(ctx context.Context, fqdn, value string) error {
	if _, err := relName(fqdn, c.zone); err != nil {
		return err
	}
	zid, err := c.zoneIDFor(ctx)
	if err != nil {
		return err
	}
	var rec struct{ ID string }
	in := map[string]any{"type": "TXT", "name": canon(fqdn), "content": `"` + value + `"`, "ttl": 60}
	if err := c.call(ctx, http.MethodPost, "/zones/"+url.PathEscape(zid)+"/dns_records", in, &rec); err != nil {
		return err
	}
	c.mu.Lock()
	c.ids[canon(fqdn)+"|"+value] = rec.ID
	c.mu.Unlock()
	return nil
}

func (c *cloudflare) CleanUp(ctx context.Context, fqdn, value string) error {
	if _, err := relName(fqdn, c.zone); err != nil {
		return err
	}
	zid, err := c.zoneIDFor(ctx)
	if err != nil {
		return err
	}
	key := canon(fqdn) + "|" + value
	c.mu.Lock()
	id, ok := c.ids[key]
	c.mu.Unlock()
	ids := []string{id}
	if !ok { // après un redémarrage : on retrouve l'enregistrement par sa valeur
		var recs []struct{ ID, Content string }
		q := "?type=TXT&name=" + url.QueryEscape(canon(fqdn))
		if err := c.call(ctx, http.MethodGet, "/zones/"+url.PathEscape(zid)+"/dns_records"+q, nil, &recs); err != nil {
			return err
		}
		ids = ids[:0]
		for _, r := range recs {
			if unquote(r.Content) == value {
				ids = append(ids, r.ID)
			}
		}
	}
	for _, i := range ids {
		if !cfIDRe(i) {
			return errors.New("Cloudflare : identifiant d'enregistrement inattendu")
		}
		if err := c.call(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zid)+"/dns_records/"+i, nil, nil); err != nil {
			return err
		}
	}
	c.mu.Lock()
	delete(c.ids, key)
	c.mu.Unlock()
	return nil
}
