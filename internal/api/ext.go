// ext.go - API des nouvelles fonctions : résolution, ma liste, suggestions, DNSSEC, TLS, HSM.
// Entrées JSON validées, chaque modification est consignée dans l'audit signé.
// Rempart ; dépend de keystore, zones, tlsutil, upstream, migrate.

package api

import (
	"bufio"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/filter"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/migrate"
	"github.com/rempart-dns/rempart/internal/secmem"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/tlsutil"
	"github.com/rempart-dns/rempart/internal/upstream"
	"github.com/rempart-dns/rempart/internal/zones"
)

// ---- résolution (profil, résolveurs, transfert conditionnel) ----

func (a *API) getResolvers(w http.ResponseWriter, r *http.Request, _ string) {
	writeJSON(w, map[string]any{
		"resolvers": a.Store.Get().Resolvers, "presets": upstream.Presets,
		"default_bootstrap": append([]string{}, a.Bootstrap...), "stats": a.Upstreams.Stats(),
	})
}

func (a *API) putResolvers(w http.ResponseWriter, r *http.Request, user string) {
	var in state.Resolvers
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Profile != "perso" && in.Profile != "entreprise" {
		jsonError(w, http.StatusBadRequest, "profil perso ou entreprise attendu")
		return
	}
	clean := func(xs []string) []string {
		out := []string{}
		for _, x := range xs {
			if x = strings.TrimSpace(x); x != "" && !slices.Contains(out, x) {
				out = append(out, x)
			}
		}
		return out
	}
	in.Upstreams, in.Bootstrap = clean(in.Upstreams), clean(in.Bootstrap)
	if len(in.Upstreams) == 0 {
		jsonError(w, http.StatusBadRequest, "au moins un résolveur est nécessaire")
		return
	}
	if in.Forwards == nil {
		in.Forwards = []state.Forward{}
	}
	for i := range in.Forwards {
		in.Forwards[i].Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.Forwards[i].Domain)), ".")
		in.Forwards[i].Servers = clean(in.Forwards[i].Servers)
	}
	if err := a.ApplyResolvers(in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	old := a.Store.Get().Resolvers
	if err := a.Store.Update(func(s *state.State) error { s.Resolvers = in; return nil }); err != nil {
		_ = a.ApplyResolvers(old)
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.Cache.Flush()
	a.record(user, "résolution.modifiée", fmt.Sprintf("profil %s, %d résolveurs, %d transferts", in.Profile, len(in.Upstreams), len(in.Forwards)))
	a.getResolvers(w, r, user)
}

// ---- liste personnelle : import en masse, export ----

// parseRuleLine accepte un domaine seul, une ligne hosts ou une règle
// Adblock (||domaine^, @@||domaine^ pour une exception).
func parseRuleLine(line string) (domain string, allow, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
		return "", false, false
	}
	if i := strings.IndexByte(line, '#'); i > 0 {
		line = strings.TrimSpace(line[:i])
	}
	if strings.HasPrefix(line, "@@") {
		allow, line = true, line[2:]
	}
	if f := strings.Fields(line); len(f) >= 2 {
		if net.ParseIP(f[0]) == nil {
			return "", false, false // plusieurs mots : ni domaine, ni ligne hosts
		}
		line = f[1] // format hosts : « 0.0.0.0 domaine »
	}
	line = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(line, "||"), "*."), "^")
	d, ok := filter.NormalizeDomain(line)
	return d, allow, ok
}

func (a *API) bulkRules(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		Text, Comment string
		Allow         bool
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	var add []state.Rule
	skipped := 0
	sc := bufio.NewScanner(strings.NewReader(in.Text))
	for sc.Scan() {
		d, allow, ok := parseRuleLine(sc.Text())
		if !ok {
			if strings.TrimSpace(sc.Text()) != "" {
				skipped++
			}
			continue
		}
		add = append(add, state.Rule{Domain: d, Allow: allow || in.Allow, Comment: in.Comment, Created: now})
	}
	if len(add) == 0 {
		jsonError(w, http.StatusBadRequest, "aucun domaine valide")
		return
	}
	if len(add) > 50000 {
		jsonError(w, http.StatusBadRequest, "50 000 règles au plus par import : utilisez plutôt une liste distante")
		return
	}
	if err := a.Store.Update(func(s *state.State) error {
		for _, rule := range add {
			s.Rules = slices.DeleteFunc(s.Rules, func(x state.Rule) bool { return x.Domain == rule.Domain })
			s.Rules = append(s.Rules, rule)
		}
		return nil
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.Cache.Flush()
	a.record(user, "règles.import", fmt.Sprintf("%d règles", len(add)))
	writeJSON(w, map[string]int{"added": len(add), "skipped": skipped})
}

func (a *API) exportRules(w http.ResponseWriter, r *http.Request, _ string) {
	format := r.URL.Query().Get("format")
	var b strings.Builder
	fmt.Fprintf(&b, "! Liste personnelle Rempart — exportée le %s\n", time.Now().UTC().Format(time.DateTime))
	if format == "hosts" {
		b.Reset()
		fmt.Fprintf(&b, "# Liste personnelle Rempart — exportée le %s (exceptions omises)\n", time.Now().UTC().Format(time.DateTime))
	}
	for _, rule := range a.Store.Get().Rules {
		switch format {
		case "hosts":
			if !rule.Allow {
				fmt.Fprintf(&b, "0.0.0.0 %s\n", rule.Domain)
			}
		case "domains":
			if !rule.Allow {
				fmt.Fprintln(&b, rule.Domain)
			}
		default:
			prefix := "||"
			if rule.Allow {
				prefix = "@@||"
			}
			fmt.Fprintf(&b, "%s%s^\n", prefix, rule.Domain)
		}
	}
	name := "rempart-liste.txt"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write([]byte(b.String()))
}

// ---- suggestions ----

func (a *API) suggestions(w http.ResponseWriter, r *http.Request, _ string) {
	st := a.Store.Get()
	writeJSON(w, map[string]any{
		"enabled": a.Suggest.Enabled(), "log_mode": st.Settings.LogMode,
		"items": a.Suggest.Analyze(a.Blocker.Matcher(), st.Dismissed, 50),
	})
}

func (a *API) dismissSuggestion(w http.ResponseWriter, r *http.Request, user string) {
	var in struct{ Domain string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	d, ok := filter.NormalizeDomain(in.Domain)
	if !ok {
		jsonError(w, http.StatusBadRequest, "nom de domaine invalide")
		return
	}
	if err := a.Store.Update(func(s *state.State) error {
		if !slices.Contains(s.Dismissed, d) {
			s.Dismissed = append(s.Dismissed, d)
		}
		if len(s.Dismissed) > 5000 {
			s.Dismissed = s.Dismissed[len(s.Dismissed)-5000:]
		}
		return nil
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.record(user, "suggestion.ignorée", d)
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- DNSSEC : clés, rotations, DS ----

func zoneName(r *http.Request) string { return strings.ToLower(dns.Fqdn(r.PathValue("name"))) }

func (a *API) zoneDS(w http.ResponseWriter, r *http.Request, _ string) {
	z := a.Zones.Get(zoneName(r))
	if z == nil || !z.DNSSEC {
		jsonError(w, http.StatusNotFound, "zone introuvable ou non signée")
		return
	}
	if r.URL.Query().Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(strings.Join(z.DS(), "\n") + "\n"))
		return
	}
	var ready []string
	for _, k := range z.Keys {
		if k.Role == "ksk" && k.State == zones.StateReady {
			ready = append(ready, k.DS)
		}
	}
	writeJSON(w, map[string]any{"zone": z.Origin, "ds": z.DS(), "pending": ready})
}

func (a *API) mutateZone(w http.ResponseWriter, r *http.Request, user, action string, fn func(*state.Zone) (string, error)) {
	name := zoneName(r)
	detail := ""
	_, err := a.saveZone(user, action, name, func(s *state.State) (*state.Zone, error) {
		for i := range s.Zones {
			if s.Zones[i].Name == name {
				d, err := fn(&s.Zones[i])
				detail = d
				return &s.Zones[i], err
			}
		}
		return nil, errors.New("zone introuvable")
	})
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if detail != "" {
		a.record(user, action+".détail", detail)
	}
	a.getZones(w, r, user)
}

func (a *API) rollover(w http.ResponseWriter, r *http.Request, user string) {
	var in struct{ Role string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.mutateZone(w, r, user, "dnssec.rotation", func(z *state.Zone) (string, error) {
		label, err := zones.StartRollover(z, in.Role, time.Now().UTC())
		return strings.ToUpper(in.Role) + " " + label, err
	})
}

// algorithmRollover démarre le passage d'une zone à un autre algorithme
// DNSSEC (RFC 6781 §4.1.4).
func (a *API) algorithmRollover(w http.ResponseWriter, r *http.Request, user string) {
	var in struct{ Algorithm string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	alg, err := keystore.ParseAlgorithm(in.Algorithm)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := keystore.Supports(a.KS, alg); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.mutateZone(w, r, user, "dnssec.rotation-algorithme", func(z *state.Zone) (string, error) {
		from := z.Algorithm
		labels, err := zones.StartAlgorithmRollover(z, string(alg), time.Now().UTC())
		return fmt.Sprintf("%s → %s, nouvelles clés %s", from, alg, strings.Join(labels, ", ")), err
	})
}

func (a *API) confirmDS(w http.ResponseWriter, r *http.Request, user string) {
	name := zoneName(r)
	err := a.Store.Update(func(s *state.State) error {
		for i := range s.Zones {
			if s.Zones[i].Name == name {
				if !zones.ConfirmDS(&s.Zones[i], time.Now().UTC(), 0) {
					return errors.New("aucune KSK n'attend la publication de son DS")
				}
				return nil
			}
		}
		return errors.New("zone introuvable")
	})
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.record(user, "dnssec.ds-confirmé", name+" : DS déclaré publié chez le parent")
	// La transition (et plus tard la destruction de l'ancienne KSK) passe par
	// le même chemin que la rotation automatique.
	a.DNSSECTick(r.Context())
	a.getZones(w, r, user)
}

func (a *API) zonePolicy(w http.ResponseWriter, r *http.Request, user string) {
	var in state.ZonePolicy
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.ZSKDays < 0 || in.ZSKDays > 3650 || in.KSKDays < 0 || in.KSKDays > 3650 || (in.ZSKDays > 0 && in.ZSKDays < 7) || (in.KSKDays > 0 && in.KSKDays < 30) {
		jsonError(w, http.StatusBadRequest, "durées invalides (ZSK : 7 jours minimum, KSK : 30 jours minimum, 0 = manuel)")
		return
	}
	a.mutateZone(w, r, user, "dnssec.politique", func(z *state.Zone) (string, error) {
		zones.Normalize(z, time.Now().UTC())
		z.Policy = in
		return fmt.Sprintf("auto=%v zsk=%dj ksk=%dj cds=%v nsec3=%v", in.AutoRollover, in.ZSKDays, in.KSKDays, in.PublishCDS, in.NSEC3), nil
	})
}

// DNSSECTick fait avancer les rotations de toutes les zones ; appelé
// périodiquement par main. Le DS des KSK prêtes est recherché chez le parent
// via les résolveurs en amont (équivalent du « checkds » de BIND).
func (a *API) DNSSECTick(ctx context.Context) {
	now := time.Now().UTC()
	seen := map[string]uint32{}
	for _, sz := range a.Store.Get().Zones {
		z := a.Zones.Get(sz.Name)
		if want := zones.ReadyDS(sz, z); len(want) > 0 {
			if ttl, ok := a.parentHasDS(ctx, sz.Name, want); ok {
				seen[sz.Name] = ttl
			}
		}
	}
	var destroy []string
	var events []string
	err := a.Store.Update(func(s *state.State) error {
		for i := range s.Zones {
			sz := &s.Zones[i]
			if ttl, ok := seen[sz.Name]; ok && zones.ConfirmDS(sz, now, ttl) {
				events = append(events, sz.Name+" : DS de la nouvelle KSK constaté chez le parent")
			}
			var maxTTL time.Duration
			live := map[string]bool{}
			if z := a.Zones.Get(sz.Name); z != nil {
				maxTTL = z.MaxTTL
				for _, k := range z.Keys {
					live[k.Label] = true
				}
			}
			ch, d := zones.Advance(sz, now, maxTTL, zones.DefaultTiming, live)
			for _, c := range ch {
				events = append(events, sz.Name+" : "+c)
			}
			destroy = append(destroy, d...)
		}
		if len(events) == 0 {
			return errNoChange
		}
		return nil
	})
	if errors.Is(err, errNoChange) {
		return
	}
	if err == nil {
		err = a.Zones.Load(a.Store.Get().Zones)
		a.Cache.Flush()
	}
	for _, e := range events {
		a.record("système", "dnssec.rotation", e)
	}
	if err != nil {
		a.record("système", "dnssec.erreur", err.Error())
		return
	}
	// Destruction après re-signature : la clé n'est plus utilisée.
	for _, l := range destroy {
		if err := a.KS.Destroy(l); err != nil {
			a.record("système", "dnssec.erreur", "destruction de "+l+" : "+err.Error())
		}
	}
}

var errNoChange = errors.New("aucun changement")

func (a *API) parentHasDS(ctx context.Context, zone string, want []string) (uint32, bool) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(zone), dns.TypeDS)
	q.SetEdns0(1232, true)
	q.AuthenticatedData = true
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, _, err := a.Upstreams.Exchange(ctx, q)
	// Seule une réponse validée par le résolveur (bit AD, RFC 6840 §5.8)
	// est prise en compte : un DS usurpé ferait retirer la KSK en service.
	// Les résolveurs proposés (Quad9, DNS4EU, Mullvad, Cloudflare, Google)
	// valident DNSSEC ; sinon, la confirmation reste manuelle.
	if err != nil || resp.Rcode != dns.RcodeSuccess || !resp.AuthenticatedData {
		return 0, false
	}
	for _, w := range want {
		rr, err := dns.NewRR(w)
		if err != nil {
			continue
		}
		wd := rr.(*dns.DS)
		for _, ans := range resp.Answer {
			if d, ok := ans.(*dns.DS); ok && d.KeyTag == wd.KeyTag && d.Algorithm == wd.Algorithm &&
				d.DigestType == wd.DigestType && strings.EqualFold(d.Digest, wd.Digest) {
				return d.Hdr.Ttl, true
			}
		}
	}
	return 0, false
}

// ---- certificat TLS ----

func (a *API) getTLS(w http.ResponseWriter, r *http.Request, _ string) {
	st := a.Store.Get().TLS
	writeJSON(w, map[string]any{
		"info": a.TLS.Info(), "config": st, "locked": a.TLS.Locked(),
		"directories": tlsutil.Directories, "http01_listen": a.HTTP01Listen,
		"needs_renewal": a.TLS.NeedsRenewal(time.Now()),
	})
}

func validNames(names []string) ([]string, error) {
	out := []string{}
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if n == "" {
			continue
		}
		if _, ok := dns.IsDomainName(n); !ok || strings.ContainsAny(n, " /") {
			return nil, fmt.Errorf("nom invalide : %q", n)
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("au moins un nom est nécessaire")
	}
	return out, nil
}

func (a *API) putTLSConfig(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		Names []string
		ACME  struct {
			DirectoryURL string `json:"directory_url"`
			Email        string
			Challenge    string
			CABundle     string `json:"ca_bundle"`
		}
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	names, err := validNames(in.Names)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.ACME.Challenge != "" && in.ACME.Challenge != "http-01" && in.ACME.Challenge != "dns-01" {
		jsonError(w, http.StatusBadRequest, "défi http-01 ou dns-01 attendu")
		return
	}
	if strings.TrimSpace(in.ACME.CABundle) != "" {
		if _, err := upstream.CertPool(in.ACME.CABundle); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := a.Store.Update(func(s *state.State) error {
		s.TLS.Names = names
		if s.TLS.ACME.DirectoryURL != in.ACME.DirectoryURL || s.TLS.ACME.CABundle != in.ACME.CABundle {
			s.TLS.ACME.AccountURL, s.TLS.ACME.EABKeyID = "", "" // autre AC : nouveau compte
		}
		s.TLS.ACME.DirectoryURL, s.TLS.ACME.Email = strings.TrimSpace(in.ACME.DirectoryURL), strings.TrimSpace(in.ACME.Email)
		s.TLS.ACME.Challenge, s.TLS.ACME.CABundle = in.ACME.Challenge, in.ACME.CABundle
		return nil
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.record(user, "tls.configuration", strings.Join(names, ", ")+" ; ACME "+in.ACME.DirectoryURL)
	a.getTLS(w, r, user)
}

func (a *API) acmeOptions() tlsutil.ACMEOptions {
	st := a.Store.Get().TLS
	return tlsutil.ACMEOptions{DirectoryURL: st.ACME.DirectoryURL, Email: st.ACME.Email, AccountURL: st.ACME.AccountURL,
		Challenge: st.ACME.Challenge, CABundle: st.ACME.CABundle, Names: st.Names, HTTPListen: a.HTTP01Listen,
		DNS01: func(fqdn, value string, add bool) error {
			return a.Zones.SetChallenge(a.Store.Get().Zones, fqdn, value, add)
		}}
}

func (a *API) acmeRegister(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		EABKeyID  string `json:"eab_key_id"`
		EABHMAC   string `json:"eab_hmac"`
		AcceptTOS bool   `json:"accept_tos"`
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	hmacKey := []byte(in.EABHMAC)
	in.EABHMAC = ""
	defer secmem.Wipe(hmacKey)
	if !in.AcceptTOS {
		jsonError(w, http.StatusBadRequest, "l'inscription vaut acceptation des conditions de l'AC")
		return
	}
	if (in.EABKeyID == "") != (len(hmacKey) == 0) {
		jsonError(w, http.StatusBadRequest, "EAB : l'identifiant et la clé HMAC vont ensemble")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	acct, err := a.TLS.Register(ctx, a.acmeOptions(), in.EABKeyID, hmacKey)
	if err != nil {
		a.record(user, "acme.inscription.échec", err.Error())
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	_ = a.Store.Update(func(s *state.State) error {
		s.TLS.ACME.AccountURL, s.TLS.ACME.EABKeyID = acct, in.EABKeyID
		return nil
	})
	a.record(user, "acme.inscription", acct)
	a.getTLS(w, r, user)
}

// IssueCertificate commande un certificat ACME et consigne le résultat ;
// utilisé par l'interface et par le renouvellement automatique.
func (a *API) IssueCertificate(ctx context.Context, actor string) error {
	now := time.Now().UTC()
	info, err := a.TLS.Obtain(ctx, a.acmeOptions())
	_ = a.Store.Update(func(s *state.State) error {
		s.TLS.ACME.LastAttempt = now
		if err != nil {
			s.TLS.ACME.LastError = err.Error()
			return nil
		}
		s.TLS.Mode, s.TLS.ACME.LastSuccess, s.TLS.ACME.LastError = "acme", now, ""
		return nil
	})
	if err != nil {
		a.record(actor, "acme.émission.échec", err.Error())
		return err
	}
	a.record(actor, "acme.émission", fmt.Sprintf("%s, émis par %s, expire le %s", strings.Join(info.Names, ", "), info.Issuer, info.NotAfter.Format(time.DateOnly)))
	return nil
}

func (a *API) acmeIssue(w http.ResponseWriter, r *http.Request, user string) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	if err := a.IssueCertificate(ctx, user); err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.getTLS(w, r, user)
}

func (a *API) tlsCSR(w http.ResponseWriter, r *http.Request, user string) {
	var in struct{ Names []string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	names, err := validNames(in.Names)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	der, err := a.TLS.CSR(names)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.record(user, "tls.csr", strings.Join(names, ", "))
	writeJSON(w, map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
}

func (a *API) tlsInstall(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		Chain string `json:"chain"`
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	info, err := a.TLS.Install([]byte(in.Chain), "manual")
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = a.Store.Update(func(s *state.State) error { s.TLS.Mode = "manual"; return nil })
	a.record(user, "tls.import", fmt.Sprintf("%s, émis par %s, expire le %s", info.Subject, info.Issuer, info.NotAfter.Format(time.DateOnly)))
	a.getTLS(w, r, user)
}

func (a *API) tlsSelfSigned(w http.ResponseWriter, r *http.Request, user string) {
	if err := a.TLS.SelfSigned(true); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = a.Store.Update(func(s *state.State) error { s.TLS.Mode = "selfsigned"; return nil })
	a.record(user, "tls.auto-signé", "")
	a.getTLS(w, r, user)
}

// ---- HSM : découverte, test, bascule ----

// hsmTested retient le dernier test réussi : la bascule n'est acceptée que
// pour un token testé avec succès dans le quart d'heure.
var hsmTested struct {
	sync.Mutex
	module, token string
	at            time.Time
	failures      []time.Time // échecs de PIN récents : protège le token du verrouillage
}

func (a *API) retiredDirs() []string {
	out := []string{}
	for _, pat := range []string{"keystore.retired-*", "migration-backup-*"} {
		m, _ := filepath.Glob(filepath.Join(a.DataDir, pat))
		out = append(out, m...)
	}
	return out
}

func (a *API) hsmStatus(w http.ResponseWriter, r *http.Request, _ string) {
	ov, err := keystore.LoadOverride(a.DataDir)
	ovErr := ""
	if err != nil {
		ovErr = err.Error()
	}
	writeJSON(w, map[string]any{
		"pkcs11_available": keystore.PKCS11Available, "backend": a.KS.Backend(), "keystore": a.KS.Describe(),
		"modules": keystore.DiscoverModules(a.ModuleDirs), "module_dirs": append([]string{}, a.ModuleDirs...), "active_module": a.ActiveModule, "active_token": a.ActiveToken,
		"override": ov, "override_error": ovErr, "failed": keystore.LoadFailed(a.DataDir), "pin_configured": a.PINConfigured, "retired": a.retiredDirs(),
		"keys": a.KS.Keys(),
	})
}

func (a *API) checkModule(module string) error {
	if !keystore.PKCS11Available {
		return errors.New("ce binaire a été compilé sans support HSM")
	}
	if err := keystore.AllowedModule(module, a.ModuleDirs); err != nil {
		return err
	}
	if a.ActiveModule != "" {
		x, _ := filepath.EvalSymlinks(module)
		y, _ := filepath.EvalSymlinks(a.ActiveModule)
		if x == y {
			return errors.New("ce module est celui du keystore en service : il ne peut pas être testé à chaud")
		}
	}
	return nil
}

func (a *API) hsmProbe(w http.ResponseWriter, r *http.Request, _ string) {
	var in struct{ Module string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.checkModule(in.Module); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	mi, tokens, err := keystore.ProbeModule(in.Module)
	if err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]any{"module": mi, "tokens": tokens})
}

func (a *API) hsmTest(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		Module, Token string
		PIN           string `json:"pin"`
		AllowFinalTry bool   `json:"allow_final_try"`
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, "requête invalide")
		return
	}
	pin := []byte(in.PIN)
	in.PIN = ""
	defer secmem.Wipe(pin)
	if err := a.checkModule(in.Module); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Tous les tokens ne signalent pas le dernier essai : au plus deux
	// échecs par quart d'heure, quoi que dise le token.
	hsmTested.Lock()
	recent := hsmTested.failures[:0]
	for _, t := range hsmTested.failures {
		if time.Since(t) < 15*time.Minute {
			recent = append(recent, t)
		}
	}
	hsmTested.failures = recent
	blocked := len(recent) >= 2
	hsmTested.Unlock()
	if blocked {
		jsonError(w, http.StatusTooManyRequests, "deux échecs récents : attendez 15 minutes et vérifiez le PIN avant de réessayer (risque de verrouillage du token)")
		return
	}
	rep, err := keystore.TestToken(in.Module, in.Token, pin, in.AllowFinalTry)
	if err != nil {
		if rep.Login == false && strings.Contains(err.Error(), "connexion refusée") {
			hsmTested.Lock()
			hsmTested.failures = append(hsmTested.failures, time.Now())
			hsmTested.Unlock()
		}
		a.record(user, "hsm.test.échec", fmt.Sprintf("token %q : %v", in.Token, err))
		writeJSON(w, map[string]any{"ok": false, "error": err.Error(), "report": rep})
		return
	}
	hsmTested.Lock()
	hsmTested.module, hsmTested.token, hsmTested.at = in.Module, in.Token, time.Now()
	hsmTested.Unlock()
	a.record(user, "hsm.test", fmt.Sprintf("token %q (%s %s, série %s) : connexion et auto-test réussis", in.Token, rep.Token.Manufacturer, rep.Token.Model, rep.Token.Serial))
	writeJSON(w, map[string]any{"ok": true, "report": rep})
}

func (a *API) hsmApply(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		Module, Token string
		KEKLabel      string `json:"kek_label"`
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if a.KS.Backend() != "software" {
		jsonError(w, http.StatusBadRequest, "Rempart utilise déjà un HSM : pour changer de token, utilisez le clonage ou la sauvegarde du constructeur (les clés ne sont pas extractibles)")
		return
	}
	if err := a.checkModule(in.Module); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	hsmTested.Lock()
	tested := hsmTested.module == in.Module && hsmTested.token == in.Token && time.Since(hsmTested.at) < 15*time.Minute
	hsmTested.Unlock()
	if !tested {
		jsonError(w, http.StatusBadRequest, "testez d'abord la connexion à ce token (le test est valable 15 minutes)")
		return
	}
	if in.KEKLabel == "" {
		in.KEKLabel = "rempart-kek"
	}
	if !keystore.ValidLabel(in.KEKLabel) {
		jsonError(w, http.StatusBadRequest, "label de KEK invalide")
		return
	}
	ov := &keystore.Override{Backend: "pkcs11", Module: in.Module, TokenLabel: in.Token, KEKLabel: in.KEKLabel,
		PendingMigration: true, RequestedBy: user, RequestedAt: time.Now().UTC()}
	if err := ov.Save(a.DataDir); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = os.Remove(keystore.OverridePath(a.DataDir) + ".failed")
	a.record(user, "hsm.bascule.demandée", fmt.Sprintf("module %s, token %q : migration au prochain démarrage", in.Module, in.Token))
	a.hsmStatus(w, r, user)
}

func (a *API) hsmCancel(w http.ResponseWriter, r *http.Request, user string) {
	ov, err := keystore.LoadOverride(a.DataDir)
	// Migration vers le HSM, ou passage à un token cloné pas encore effectué.
	cloneSwitch := ov != nil && !ov.PendingMigration && ov.MigratedAt.IsZero() && ov.TokenLabel != a.ActiveToken
	if err != nil || ov == nil || !(ov.PendingMigration || cloneSwitch) {
		jsonError(w, http.StatusBadRequest, "aucune bascule en attente")
		return
	}
	if err := os.Remove(keystore.OverridePath(a.DataDir)); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.record(user, "hsm.bascule.annulée", "")
	a.hsmStatus(w, r, user)
}

func (a *API) hsmDestroyRetired(w http.ResponseWriter, r *http.Request, user string) {
	var in struct{ Path string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !slices.Contains(a.retiredDirs(), in.Path) {
		jsonError(w, http.StatusBadRequest, "dossier inconnu")
		return
	}
	if a.KS.Backend() != "pkcs11" {
		jsonError(w, http.StatusBadRequest, "destruction possible seulement une fois le HSM en service")
		return
	}
	if err := migrate.DestroyRetired(in.Path); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.record(user, "hsm.ancien-keystore.détruit", filepath.Base(in.Path))
	a.hsmStatus(w, r, user)
}
