// encrypted.go - démarrage et arrêt à chaud des écoutes DNS-over-TLS, DNS-over-HTTPS et DNS-over-QUIC.
// Entrées : adresses de dot.listen, doh.listen et doq.listen, état Encryption choisi dans l'interface.
// Contexte : Rempart ; le port n'est jamais choisi ici, il vient du fichier de configuration.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/dnscrypt"
	"github.com/rempart-dns/rempart/internal/state"
)

// ListenerStatus décrit une écoute chiffrée pour l'interface.
type ListenerStatus struct {
	Listen  string `json:"listen"`         // vide : absente du fichier de configuration
	Path    string `json:"path,omitempty"` // DoH seulement
	Enabled bool   `json:"enabled"`        // choix de l'administrateur
	Running bool   `json:"running"`
	Error   string `json:"error,omitempty"`
	Stamp   string `json:"stamp,omitempty"` // DNSCrypt seulement
}

// EncryptionStatus regroupe DoT, DoH et DoQ.
type EncryptionStatus struct {
	DoT ListenerStatus `json:"dot"`
	DoH ListenerStatus `json:"doh"`
	DoQ ListenerStatus `json:"doq"`
	// DNSCrypt : tampon sdns:// et nom de fournisseur.
	DNSCrypt ListenerStatus `json:"dnscrypt"`
	Provider string         `json:"dnscrypt_provider,omitempty"`
	// DoTTokenAdmit : jeton d'appareil DoT accepté depuis Internet.
	DoTTokenAdmit bool `json:"dot_token_admit"`
	// WebOnDoH : interface aussi servie sur l'écoute DoH (réseaux autorisés).
	WebOnDoH bool `json:"web_on_doh"`
}

// Encrypted pilote les écoutes DoT et DoH d'un Server.
type Encrypted struct {
	srv     *Server
	tlsConf *tls.Config
	dotAddr string
	dohAddr string
	dohPath string
	doqAddr string

	mu      sync.Mutex
	dot     *dns.Server
	doh     *http.Server
	dohLn   net.Listener
	doq     *DoQ
	dcAddr  string
	dcStamp string
	dcSrv   *dnscrypt.Server
	dc      *DNSCrypt
	dcErr   error
	enc     state.Encryption
	dotErr  error
	dohErr  error
	doqErr  error

	// web : gestionnaire de l'interface, servi sous « / » de l'écoute DoH
	// quand webOnDoH est actif (choisi à chaud, sans redémarrer l'écoute).
	web      atomic.Pointer[http.Handler]
	webOnDoH atomic.Bool
}

// SetWebHandler déclare l'interface d'administration, à servir aussi sur
// l'écoute DoH si l'administrateur le choisit.
func (e *Encrypted) SetWebHandler(h http.Handler) { e.web.Store(&h) }

// webGate sert l'interface sous l'écoute DoH aux seuls clients des réseaux
// autorisés : depuis Internet (port 443 redirigé pour DoH), elle n'existe pas.
func (e *Encrypted) webGate(w http.ResponseWriter, r *http.Request) {
	h := e.web.Load()
	if !e.webOnDoH.Load() || h == nil {
		http.NotFound(w, r)
		return
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !e.srv.allowed(ap.Addr()) {
		http.NotFound(w, r)
		return
	}
	(*h).ServeHTTP(w, r)
}

// NewEncrypted ne démarre rien : appeler Apply.
func NewEncrypted(srv *Server, tlsConf *tls.Config, dotAddr, dohAddr, dohPath, doqAddr string) *Encrypted {
	return &Encrypted{srv: srv, tlsConf: tlsConf, dotAddr: dotAddr, dohAddr: dohAddr, dohPath: dohPath, doqAddr: doqAddr}
}

// SetDNSCrypt déclare l'écoute DNSCrypt (adresse du fichier de
// configuration) ; stampAddr est l'adresse publique annoncée dans le tampon.
func (e *Encrypted) SetDNSCrypt(addr string, dc *dnscrypt.Server, stampAddr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dcAddr, e.dcSrv, e.dcStamp = addr, dc, stampAddr
}

func (e *Encrypted) applyDNSCrypt(want bool) error {
	switch {
	case want && e.dc == nil:
		d, err := e.srv.ListenDNSCrypt(e.dcAddr, e.dcSrv)
		if err != nil {
			return fmt.Errorf("écoute DNSCrypt %s: %w", e.dcAddr, err)
		}
		e.dc = d
		e.srv.Logger.Info("DNSCrypt en écoute", "addr", e.dcAddr, "fournisseur", e.dcSrv.ProviderName)
	case !want && e.dc != nil:
		_ = e.dc.Close()
		e.dc = nil
		e.srv.Logger.Info("DNSCrypt arrêté", "addr", e.dcAddr)
	}
	return nil
}

// Apply démarre ou arrête chaque écoute selon enc. Une écoute absente du
// fichier de configuration reste éteinte quel que soit enc. En cas d'échec,
// l'erreur est rendue et reste visible dans Status ; l'autre écoute est
// quand même traitée.
func (e *Encrypted) Apply(enc state.Encryption) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enc = enc
	e.srv.SetDoTTokenAdmit(enc.DoTTokenAdmit)
	e.webOnDoH.Store(enc.WebOnDoH)
	e.dotErr = e.applyDoT(e.dotAddr != "" && !enc.DoTDisabled)
	e.dohErr = e.applyDoH(e.dohAddr != "" && !enc.DoHDisabled)
	e.doqErr = e.applyDoQ(e.doqAddr != "" && !enc.DoQDisabled)
	e.dcErr = e.applyDNSCrypt(e.dcAddr != "" && e.dcSrv != nil && enc.DNSCryptEnabled)
	return errors.Join(e.dotErr, e.dohErr, e.doqErr, e.dcErr)
}

func (e *Encrypted) applyDoQ(want bool) error {
	switch {
	case want && e.doq == nil:
		d, err := e.srv.ListenDoQ(e.doqAddr, e.tlsConf)
		if err != nil {
			return fmt.Errorf("écoute DoQ %s: %w", e.doqAddr, err)
		}
		e.doq = d
		e.srv.Logger.Info("DNS-over-QUIC en écoute", "addr", e.doqAddr)
	case !want && e.doq != nil:
		_ = e.doq.Close()
		e.doq = nil
		e.srv.Logger.Info("DNS-over-QUIC arrêté", "addr", e.doqAddr)
	}
	return nil
}

func (e *Encrypted) applyDoT(want bool) error {
	switch {
	case want && e.dot == nil:
		srv, err := e.srv.ListenDoT(e.dotAddr, e.tlsConf)
		if err != nil {
			return fmt.Errorf("écoute DoT %s: %w", e.dotAddr, err)
		}
		e.dot = srv
		e.srv.Logger.Info("DNS-over-TLS en écoute", "addr", e.dotAddr)
	case !want && e.dot != nil:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.srv.Stop(ctx, e.dot)
		e.dot = nil
		e.srv.Logger.Info("DNS-over-TLS arrêté", "addr", e.dotAddr)
	}
	return nil
}

func (e *Encrypted) applyDoH(want bool) error {
	switch {
	case want && e.doh == nil:
		// Écoute ouverte ici, avant le service : un port occupé est signalé
		// à l'administrateur au lieu d'arrêter le processus.
		ln, err := net.Listen("tcp", e.dohAddr)
		if err != nil {
			return fmt.Errorf("écoute DoH %s: %w", e.dohAddr, err)
		}
		mux := http.NewServeMux()
		h := e.srv.DoHHandler(e.dohPath)
		mux.Handle(e.dohPath, h)
		mux.Handle(strings.TrimSuffix(e.dohPath, "/")+"/", h) // <chemin>/<jeton d'appareil>
		mux.HandleFunc("/", e.webGate)
		// Délais de l'interface (sauvegardes longues) : ils couvrent aussi DoH.
		hs := &http.Server{Handler: mux, TLSConfig: e.tlsConf,
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 3 * time.Minute,
			IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 32 << 10}
		go func() {
			if err := hs.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				e.srv.Logger.Error("DNS-over-HTTPS arrêté", "addr", e.dohAddr, "err", err)
			}
		}()
		e.doh, e.dohLn = hs, ln
		e.srv.Logger.Info("DNS-over-HTTPS en écoute", "addr", e.dohAddr, "chemin", e.dohPath)
	case !want && e.doh != nil:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.doh.Shutdown(ctx)
		// Shutdown ne ferme que les écoutes déjà prises en charge par
		// ServeTLS : si la goroutine n'a pas encore démarré, l'écoute
		// resterait ouverte et le port occupé.
		_ = e.dohLn.Close()
		e.doh, e.dohLn = nil, nil
		e.srv.Logger.Info("DNS-over-HTTPS arrêté", "addr", e.dohAddr)
	}
	return nil
}

// Status rend l'état courant des deux écoutes.
func (e *Encrypted) Status() EncryptionStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := EncryptionStatus{
		DoT:           ListenerStatus{Listen: e.dotAddr, Enabled: e.dotAddr != "" && !e.enc.DoTDisabled, Running: e.dot != nil},
		DoH:           ListenerStatus{Listen: e.dohAddr, Path: e.dohPath, Enabled: e.dohAddr != "" && !e.enc.DoHDisabled, Running: e.doh != nil},
		DoQ:           ListenerStatus{Listen: e.doqAddr, Enabled: e.doqAddr != "" && !e.enc.DoQDisabled, Running: e.doq != nil},
		DoTTokenAdmit: e.enc.DoTTokenAdmit,
		WebOnDoH:      e.enc.WebOnDoH,
	}
	if e.doqErr != nil {
		st.DoQ.Error = e.doqErr.Error()
	}
	st.DNSCrypt = ListenerStatus{Listen: e.dcAddr, Enabled: e.dcAddr != "" && e.enc.DNSCryptEnabled, Running: e.dc != nil}
	if e.dcErr != nil {
		st.DNSCrypt.Error = e.dcErr.Error()
	}
	if e.dcSrv != nil {
		st.Provider = strings.TrimSuffix(e.dcSrv.ProviderName, ".")
		addr := e.dcStamp
		if addr == "" {
			addr = e.dcAddr
		}
		st.DNSCrypt.Stamp = e.dcSrv.Stamp(addr, true, false, false)
	}
	if e.dotErr != nil {
		st.DoT.Error = e.dotErr.Error()
	}
	if e.dohErr != nil {
		st.DoH.Error = e.dohErr.Error()
	}
	return st
}

// Listeners complète la liste des écoutes affichée dans le tableau de bord.
func (e *Encrypted) Listeners() map[string]string {
	st := e.Status()
	out := map[string]string{}
	if st.DoT.Running {
		out["dot "+st.DoT.Listen] = "DNS-over-TLS"
	}
	if st.DoH.Running {
		out["doh "+st.DoH.Listen] = "DNS-over-HTTPS " + st.DoH.Path
	}
	if st.DoQ.Running {
		out["doq "+st.DoQ.Listen] = "DNS-over-QUIC"
	}
	if st.DNSCrypt.Running {
		out["dnscrypt "+st.DNSCrypt.Listen] = "DNSCrypt " + st.Provider
	}
	return out
}

// Close arrête les deux écoutes, à l'arrêt du processus.
func (e *Encrypted) Close() {
	_ = e.Apply(state.Encryption{DoTDisabled: true, DoHDisabled: true, DoQDisabled: true})
}
