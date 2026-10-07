// Command rempart is a privacy-first DNS filtering resolver with DNSSEC
// signing of local zones and optional HSM (PKCS#11) key protection.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata" // plages horaires : fuseaux disponibles même sans tzdata dans l'image

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/api"
	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/auditfwd"
	"github.com/rempart-dns/rempart/internal/authority"
	"github.com/rempart-dns/rempart/internal/blocker"
	"github.com/rempart-dns/rempart/internal/cache"
	"github.com/rempart-dns/rempart/internal/config"
	"github.com/rempart-dns/rempart/internal/dhcp"
	"github.com/rempart-dns/rempart/internal/dnscrypt"
	"github.com/rempart-dns/rempart/internal/dnssec"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/metrics"
	"github.com/rempart-dns/rempart/internal/migrate"
	"github.com/rempart-dns/rempart/internal/policy"
	"github.com/rempart-dns/rempart/internal/querylog"
	"github.com/rempart-dns/rempart/internal/replica"
	"github.com/rempart-dns/rempart/internal/rpz"
	"github.com/rempart-dns/rempart/internal/secmem"
	"github.com/rempart-dns/rempart/internal/server"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/suggest"
	"github.com/rempart-dns/rempart/internal/tlsutil"
	"github.com/rempart-dns/rempart/internal/tsig"
	"github.com/rempart-dns/rempart/internal/upstream"
	"github.com/rempart-dns/rempart/internal/zones"
	"github.com/rempart-dns/rempart/web"
)

var version = "1.1.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println("rempart", version, "— HSM PKCS#11:", keystore.PKCS11Available)
			return
		case "healthcheck":
			os.Exit(healthcheck(os.Args[2:]))
		case "unseal":
			os.Exit(cmdUnseal(os.Args[2:]))
		case "approve":
			os.Exit(cmdApprove(os.Args[2:]))
		case "passwd":
			os.Exit(cmdPasswd(os.Args[2:]))
		case "backup":
			os.Exit(cmdBackup(os.Args[2:]))
		case "restore":
			os.Exit(cmdRestore(os.Args[2:]))
		case "setup-secrets":
			os.Exit(cmdSetupSecrets(os.Args[2:]))
		case "hash-password":
			// Le mot de passe est lu sur l'entrée standard : passé en argument,
			// il serait visible dans ps et dans l'historique du shell.
			if len(os.Args) != 2 {
				fmt.Fprintln(os.Stderr, "usage: rempart hash-password < fichier (ou saisie puis Ctrl-D)")
				os.Exit(2)
			}
			raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			pw := strings.TrimRight(string(raw), "\r\n")
			if err := api.ValidatePassword(pw); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			fmt.Println(api.HashPassword(pw))
			return
		default:
			// Une sous-commande inconnue (binaire plus ancien que la commande
			// tapée, faute de frappe) ne doit pas lancer un second serveur.
			if !strings.HasPrefix(os.Args[1], "-") {
				fmt.Fprintf(os.Stderr, "commande inconnue %q : version, healthcheck, setup-secrets, hash-password, unseal, approve, passwd, backup verify, restore, ou -config <fichier>\n", os.Args[1])
				os.Exit(2)
			}
		}
	}
	cfgPath := flag.String("config", envOr("REMPART_CONFIG", "rempart.yaml"), "fichier de configuration YAML")
	flag.Parse()
	if err := run(*cfgPath); err != nil {
		slog.Error("arrêt sur erreur", "err", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func healthcheck(args []string) int {
	addr := "127.0.0.1:53"
	if len(args) > 0 {
		addr = args[0]
	}
	m := new(dns.Msg)
	m.SetQuestion("healthcheck.rempart.", dns.TypeA)
	c := &dns.Client{Timeout: 2 * time.Second}
	if _, _, err := c.Exchange(m, addr); err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		return 1
	}
	return 0
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)
	log.Info("démarrage de Rempart", "version", version, "config", cfgPath)

	hardening := secmem.Harden()
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}

	// ---- keystore ----
	// keystore.json (écrit par l'assistant HSM de l'interface) l'emporte sur
	// la section keystore du fichier de configuration.
	ov, err := keystore.LoadOverride(cfg.DataDir)
	if err != nil {
		return err
	}
	if ov != nil {
		if err := keystore.AllowedModule(ov.Module, cfg.Keystore.PKCS11.ModuleDirs); err != nil {
			return fmt.Errorf("keystore.json : %w", err)
		}
	}
	ks, err := openKeystore(cfg, ov, log)
	if err != nil {
		return err
	}
	defer ks.Close()
	log.Info("keystore ouvert", "backend", ks.Backend(), "détail", ks.Describe())

	// ---- state ----
	statePath := filepath.Join(cfg.DataDir, "state.sealed")
	adminPass, _ := config.Secret("REMPART_ADMIN_PASSWORD", "")
	if _, err := os.Stat(statePath); errors.Is(err, os.ErrNotExist) {
		// Au premier démarrage, le mot de passe administrateur doit être
		// fourni : un mot de passe généré puis écrit dans les journaux
		// resterait lisible dans ceux-ci.
		if adminPass == "" {
			return errors.New("premier démarrage : fournissez le mot de passe administrateur par REMPART_ADMIN_PASSWORD_FILE (voir scripts/install.sh ou rempart setup-secrets)")
		}
		if err := api.ValidatePassword(adminPass); err != nil {
			return fmt.Errorf("REMPART_ADMIN_PASSWORD : %w", err)
		}
	}
	store, created, err := state.Open(ks, statePath, defaultState(cfg, adminPass))
	if err != nil {
		return err
	}
	adminPass = ""
	if created {
		log.Info("compte administrateur créé", "utilisateur", "admin")
	}
	// Données antérieures aux nouvelles fonctions : profil, résolveurs,
	// certificat et suivi des clés DNSSEC.
	if err := store.Update(func(s *state.State) error {
		migrateState(s, cfg)
		return nil
	}); err != nil {
		return err
	}
	// Premier démarrage : les zones de defaults.zones viennent d'être créées,
	// leurs clés DNSSEC n'existent pas encore. Plus tard, une clé absente
	// reste une erreur et n'est jamais régénérée en silence.
	if created {
		for _, z := range store.Get().Zones {
			if z.DNSSEC {
				if err := zones.GenerateKeys(ks, z); err != nil {
					return fmt.Errorf("zone %s : %w", z.Name, err)
				}
			}
		}
	}

	al, err := audit.Open(ks, cfg.DataDir)
	if err != nil {
		return err
	}
	_ = al.Add("système", "démarrage", fmt.Sprintf("version %s, keystore %s", version, ks.Backend()))
	if len(unsealedBy) > 0 {
		_ = al.Add("système", "keystore.déverrouillé", "quorum : "+strings.Join(unsealedBy, ", "))
	}
	// Secours : téléphone et codes de secours perdus. Seul quelqu'un qui
	// contrôle l'environnement du serveur peut le faire, et c'est audité.
	if adm := store.Get().Admin; os.Getenv("REMPART_RESET_OTP") == "1" && (adm.TOTPSecret != "" || len(adm.Passkeys) > 0) {
		if err := store.Update(func(s *state.State) error {
			s.Admin.TOTPSecret, s.Admin.TOTPLast, s.Admin.Recovery, s.Admin.Passkeys = "", 0, nil, nil
			return nil
		}); err != nil {
			return err
		}
		_ = al.Add("système", "otp.réinitialisé", fmt.Sprintf("REMPART_RESET_OTP=1 au démarrage (TOTP et %d clé(s) d'accès retirés)", len(adm.Passkeys)))
		log.Warn("double authentification et clés d'accès retirées par REMPART_RESET_OTP : retirez cette variable et réactivez-les depuis l'interface")
	}
	if rep := al.Verify(); !rep.OK {
		log.Error("ALERTE : le journal d'audit a été altéré", "problème", rep.Problem)
	}

	// ---- services ----
	qlog, err := querylog.New(ks, cfg.DataDir, log)
	if err != nil {
		return err
	}
	zm := zones.NewManager(ks, log)
	if err := zm.Load(store.Get().Zones); err != nil {
		log.Error("chargement des zones locales", "err", err)
	}
	eng, err := blocker.New(store, cfg.DataDir, nil, log)
	if err != nil {
		return err
	}
	applyResolvers := func(r state.Resolvers) error { return nil }
	router := &upstream.Router{}
	applyResolvers = func(r state.Resolvers) error {
		roots, err := upstream.CertPool(r.ExtraCAs)
		if err != nil {
			return err
		}
		boot := r.Bootstrap
		if len(boot) == 0 {
			boot = cfg.Bootstrap
		}
		var fwd []upstream.Forward
		for _, f := range r.Forwards {
			fwd = append(fwd, upstream.Forward{Domain: f.Domain, Servers: f.Servers})
		}
		return router.Set(r.Upstreams, fwd, upstream.Options{Bootstrap: boot, RootCAs: roots})
	}
	if err := applyResolvers(store.Get().Resolvers); err != nil {
		return fmt.Errorf("résolveurs en amont : %w", err)
	}
	obs := suggest.New()
	c := cache.New(cfg.DNS.Cache.Size, cfg.DNS.Cache.MinTTL.Duration, cfg.DNS.Cache.MaxTTL.Duration)

	dh, err := dhcp.New(ks, filepath.Join(cfg.DataDir, "dhcp-leases.sealed"), log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Autorité (transferts, NOTIFY, mises à jour), flux RPZ, copie de
	// l'audit, réplication.
	prov := tsig.NewProvider()
	prov.Set(store.Get().TSIGKeys)
	record := func(actor, action, detail string) { _ = al.Add(actor, action, detail) }
	auth := &authority.Authority{Store: store, Zones: zm, Prov: prov, KS: ks, DataDir: cfg.DataDir, Log: log, Record: record}
	rpzEng := &rpz.Engine{KS: ks, DataDir: cfg.DataDir, Log: log, Prov: prov}
	auth.OnNotify = rpzEng.OnNotify
	zm.OnLoad = auth.NotifyAll
	fwd := &auditfwd.Forwarder{Audit: al, DataDir: cfg.DataDir, Log: log}
	al.OnAdd = func(audit.Event) { fwd.Wake() }
	repl := &replica.Client{Store: store, Log: log, Event: func(action, detail string) { record("réplication", action, detail) }}
	repl.Applied = func(int) {
		record("réplication", "réplication.appliquée", "configuration reçue de l'instance principale")
	}

	srv := &server.Server{Zones: zm, Blocker: eng, Cache: c, Upstreams: router, Log: qlog, Logger: log, Observer: obs,
		ACL: cfg.AllowedPrefixes, RebindAllowed: cfg.DNS.RebindAllowedDomains,
		Limiter:   server.NewLimiter(cfg.DNS.RateLimit.QPS, cfg.DNS.RateLimit.Burst),
		Neighbors: dh, Hosts: dh, TSIG: prov, Authority: auth, RPZ: rpzEng,
		Latency: metrics.NewHistogram(0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5)}
	// Validation DNSSEC locale : ancres de la racine, plus celles du fichier
	// de configuration (zones internes signées). Les domaines transférés vers
	// un serveur interne sont des ancres négatives.
	validator, err := dnssec.New(router, append(append([]string{}, dnssec.RootAnchors...), cfg.DNSSEC.TrustAnchors...))
	if err != nil {
		return err
	}
	validator.NTA = router.Forwarded
	srv.Validator = validator
	var resolversMu sync.Mutex // apply peut être appelé depuis plusieurs goroutines
	lastResolvers := store.Get().Resolvers
	apply := func(st state.State) {
		srv.SetSettings(st)
		prov.Set(st.TSIGKeys)
		// L'API valide les groupes avant de les enregistrer ; une entrée
		// devenue invalide (catalogue changé) est seulement écartée.
		p, errs := policy.Build(st)
		for _, err := range errs {
			log.Error("politique des groupes : entrée écartée", "err", err)
		}
		srv.SetPolicy(p)
		applyDHCP(dh, st, log)
		qlog.Configure(st.Settings.LogMode, st.Settings.ClientIDs, st.Settings.RetentionDays)
		// Les suggestions observent les noms résolus : jamais en mode « aucun journal ».
		obs.Enable(st.Settings.Suggestions && st.Settings.LogMode != "none")
		auth.Reconcile(ctx, st)
		rpzEng.Reconcile(ctx, st)
		fwd.Configure(st.Syslog)
		repl.Reconcile(ctx, st)
		// Résolveurs reçus par réplication (l'API les applique elle-même).
		resolversMu.Lock()
		if !reflect.DeepEqual(st.Resolvers, lastResolvers) {
			lastResolvers = st.Resolvers
			if err := applyResolvers(st.Resolvers); err != nil {
				log.Error("résolveurs reçus non appliqués", "err", err)
			}
		}
		resolversMu.Unlock()
	}
	apply(store.Get())
	store.Subscribe(apply)
	auth.NotifyAll(zm.All()) // secondaires prévenus du redémarrage

	go eng.Run(ctx, cfg.ListsRefresh.Duration)
	listeners := map[string]string{}
	for _, addr := range cfg.DNS.Listen {
		if err := srv.ListenDNS(addr); err != nil {
			if isIPv6Unavailable(addr, err) {
				log.Warn("IPv6 indisponible, écoute ignorée", "addr", addr)
				continue
			}
			return fmt.Errorf("écoute DNS %s: %w", addr, err)
		}
		listeners["dns "+addr] = "udp+tcp"
		log.Info("DNS en écoute", "addr", addr)
	}

	tst := store.Get().TLS
	tlsMgr, err := tlsutil.New(ks, tlsutil.Options{CertFile: cfg.TLS.CertFile, KeyFile: cfg.TLS.KeyFile, KeyLabel: cfg.TLS.KeyLabel, SelfSignedNames: cfg.TLS.SelfSignedNames, DataDir: cfg.DataDir}, tst.Mode, tst.Names, log)
	if err != nil {
		return fmt.Errorf("TLS: %w", err)
	}
	tlsConf := tlsMgr.Config()
	// DoT et DoH : adresses du fichier de configuration, allumés ou éteints
	// à chaud depuis l'interface (Réglages → Chiffrement).
	enc := server.NewEncrypted(srv, tlsConf, cfg.DoT.Listen, cfg.DoH.Listen, cfg.DoH.Path, cfg.DoQ.Listen)
	if cfg.DNSCrypt.Listen != "" {
		// Clé de fournisseur Ed25519 dans le keystore (HSM compris) ; les
		// clés de résolveur, éphémères, ne quittent pas la mémoire.
		prov, err := ks.Signer(cfg.DNSCrypt.KeyLabel, keystore.Ed25519, true)
		if err != nil {
			return fmt.Errorf("clé de fournisseur DNSCrypt : %w", err)
		}
		dc, err := dnscrypt.New(cfg.DNSCrypt.ProviderName, prov)
		if err != nil {
			return fmt.Errorf("DNSCrypt : %w", err)
		}
		enc.SetDNSCrypt(cfg.DNSCrypt.Listen, dc, cfg.DNSCrypt.StampAddr)
	}
	if err := enc.Apply(store.Get().Encryption); err != nil {
		return err
	}
	var httpServers []*http.Server

	activeModule, activeToken := "", ""
	if ks.Backend() == "pkcs11" {
		activeModule, activeToken = cfg.Keystore.PKCS11.Module, cfg.Keystore.PKCS11.TokenLabel
		if ov != nil {
			activeModule, activeToken = ov.Module, ov.TokenLabel
		}
	}
	pinSet := os.Getenv("REMPART_PKCS11_PIN") != "" || os.Getenv("REMPART_PKCS11_PIN_FILE") != "" || cfg.Keystore.PKCS11.PINFile != ""
	a := &api.API{Store: store, Blocker: eng, Zones: zm, Server: srv, QLog: qlog, Audit: al, KS: ks, Cache: c,
		Upstreams: router, TLS: tlsMgr, Suggest: obs, DHCP: dh, Authority: auth, RPZ: rpzEng, Forwarder: fwd, Replica: repl,
		Resealers: []func() error{auth.Reseal, rpzEng.Reseal}, Version: version, Started: time.Now(), Hardening: hardening,
		AdminACL: cfg.AdminPrefixes, SecureCk: cfg.Web.TLS, Listeners: listeners, Web: web.FS(),
		DataDir: cfg.DataDir, ModuleDirs: cfg.Keystore.PKCS11.ModuleDirs, ActiveModule: activeModule, ActiveToken: activeToken,
		Bootstrap: cfg.Bootstrap, HTTP01Listen: cfg.TLS.ACMEHTTPListen, PINConfigured: pinSet, Encrypted: enc,
		ApplyResolvers: applyResolvers,
		ServerPassphrase: func() (string, error) {
			return config.Secret("REMPART_KEYSTORE_PASSPHRASE", cfg.Keystore.Software.PassphraseFile)
		}}
	go background(ctx, log, a, zm, store, tlsMgr)
	if _, ok := ks.(*keystore.Software); ok {
		go serveApprovals(ctx, cfg, a, log)
	}
	// Un seul gestionnaire (sessions comprises) pour l'écoute de l'interface
	// et, si l'administrateur le choisit, l'écoute DoH.
	webHandler := a.Handler(cfg.Web.SessionTTL.Duration)
	enc.SetWebHandler(webHandler)
	ws := &http.Server{Addr: cfg.Web.Listen, Handler: webHandler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 3 * time.Minute,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 32 << 10}
	if cfg.Web.TLS {
		ws.TLSConfig = tlsConf
	}
	go serve(log, ws, cfg.Web.TLS)
	httpServers = append(httpServers, ws)
	scheme := "http"
	if cfg.Web.TLS {
		scheme = "https"
	}
	listeners["web "+cfg.Web.Listen] = "interface d'administration (" + scheme + ")"
	log.Info("interface web en écoute", "url", scheme+"://"+cfg.Web.Listen)

	<-ctx.Done()
	log.Info("arrêt en cours…")
	_ = al.Add("système", "arrêt", "")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, hs := range httpServers {
		_ = hs.Shutdown(sctx)
	}
	enc.Close()
	srv.Shutdown(sctx)
	dh.Apply(nil)
	_ = dh.Flush()
	qlog.Flush()
	return nil
}

func serve(log *slog.Logger, hs *http.Server, useTLS bool) {
	var err error
	if useTLS {
		err = hs.ListenAndServeTLS("", "")
	} else {
		err = hs.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serveur HTTP arrêté", "addr", hs.Addr, "err", err)
		os.Exit(1)
	}
}

func isIPv6Unavailable(addr string, err error) bool {
	host, _, _ := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil && (errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT))
}

// openKeystore ouvre le keystore configuré et, si l'administrateur l'a
// demandé depuis l'interface, migre les données du keystore logiciel vers le
// HSM avant tout autre traitement. En cas d'échec de la migration, Rempart
// continue avec le keystore logiciel et l'erreur s'affiche dans l'interface.
// unsealedBy : dépositaires qui ont déverrouillé le keystore au démarrage
// (inscrits dans l'audit dès qu'il est ouvert).
var unsealedBy []string

func openKeystore(cfg *config.Config, ov *keystore.Override, log *slog.Logger) (keystore.Keystore, error) {
	openSoftware := func() (*keystore.Software, error) {
		pass, err := config.Secret("REMPART_KEYSTORE_PASSPHRASE", cfg.Keystore.Software.PassphraseFile)
		if err != nil {
			return nil, err
		}
		sw, warn, err := keystore.OpenSoftware(cfg.Keystore.Software.Dir, pass)
		pass = ""
		if errors.Is(err, keystore.ErrQuorumRequired) {
			sw, unsealedBy, err = waitUnseal(cfg, log)
		}
		if err != nil {
			return nil, err
		}
		if warn != "" {
			log.Warn(warn)
		}
		return sw, nil
	}
	openHSM := func(module, token, kek string) (keystore.Keystore, error) {
		pin, err := config.Secret("REMPART_PKCS11_PIN", cfg.Keystore.PKCS11.PINFile)
		if err != nil {
			return nil, err
		}
		if pin == "" {
			return nil, errors.New("PIN du HSM absent : définissez REMPART_PKCS11_PIN_FILE (secret Podman) ou keystore.pkcs11.pin_file")
		}
		return keystore.OpenPKCS11(keystore.PKCS11Config{Module: module, TokenLabel: token, PIN: pin, KEKLabel: kek})
	}
	if ov == nil {
		if cfg.Keystore.Backend == "pkcs11" {
			return openHSM(cfg.Keystore.PKCS11.Module, cfg.Keystore.PKCS11.TokenLabel, cfg.Keystore.PKCS11.KEKLabel)
		}
		return openSoftware()
	}
	if !ov.PendingMigration {
		return openHSM(ov.Module, ov.TokenLabel, ov.KEKLabel)
	}
	// Migration demandée depuis l'interface.
	fail := func(sw *keystore.Software, err error) (keystore.Keystore, error) {
		log.Error("migration vers le HSM impossible, keystore logiciel conservé", "err", err)
		ov.PendingMigration, ov.LastError = false, err.Error()
		if serr := ov.Save(cfg.DataDir); serr == nil {
			// Mis de côté : au prochain démarrage, le keystore logiciel reste
			// utilisé ; l'interface affiche l'erreur.
			_ = os.Rename(keystore.OverridePath(cfg.DataDir), keystore.OverridePath(cfg.DataDir)+".failed")
		}
		return sw, nil
	}
	sw, err := openSoftware()
	if err != nil {
		return nil, err
	}
	hsm, err := openHSM(ov.Module, ov.TokenLabel, ov.KEKLabel)
	if err != nil {
		return fail(sw, err)
	}
	log.Info("migration du keystore logiciel vers le HSM", "token", ov.TokenLabel)
	rep, err := migrate.Run(cfg.DataDir, sw, hsm)
	if errors.Is(err, migrate.ErrPartial) {
		// Des fichiers sont déjà chiffrés par le HSM : on ne revient pas au
		// keystore logiciel. La demande reste en attente et le prochain
		// démarrage reprend la migration là où elle s'est arrêtée.
		hsm.Close()
		return nil, fmt.Errorf("migration vers le HSM interrompue, relancez Rempart pour la reprendre : %w", err)
	}
	if err != nil {
		hsm.Close()
		return fail(sw, err)
	}
	// La fin de migration est enregistrée avant de retirer l'ancien keystore :
	// un arrêt entre les deux laisse seulement un dossier à retirer à la main.
	dir := sw.Dir()
	sw.Close()
	ov.PendingMigration, ov.LastError = false, ""
	ov.MigratedAt, ov.MigratedKeys = time.Now().UTC(), rep.Keys
	if err := ov.Save(cfg.DataDir); err != nil {
		return nil, err
	}
	if retired, err := migrate.RetireSoftware(dir); err != nil {
		log.Warn("ancien keystore logiciel non renommé", "err", err)
	} else {
		ov.RetiredDir = retired
		_ = ov.Save(cfg.DataDir)
	}
	log.Info("migration terminée", "clés", len(rep.Keys), "fichiers", len(rep.Files), "sauvegarde", rep.BackupDir)
	return hsm, nil
}

// applyDHCP démarre, reconfigure ou arrête le serveur DHCP selon l'état.
func applyDHCP(dh *dhcp.Server, st state.State, log *slog.Logger) {
	if !st.DHCP.Enabled {
		dh.Apply(nil)
		return
	}
	var zs []string
	for _, z := range st.Zones {
		zs = append(zs, z.Name)
	}
	cfg, err := dhcp.Compile(st.DHCP, zs)
	if err != nil {
		log.Error("configuration DHCP refusée, serveur arrêté", "err", err)
		dh.Fail("configuration refusée, serveur arrêté : " + err.Error())
		return
	}
	dh.Apply(cfg)
}

// migrateState complète un état créé par une version antérieure.
func migrateState(s *state.State, cfg *config.Config) {
	if s.Resolvers.Profile == "" {
		s.Resolvers.Profile = "perso"
	}
	if len(s.Resolvers.Upstreams) == 0 {
		s.Resolvers.Upstreams = append([]string{}, cfg.Upstreams...)
	}
	if s.TLS.Mode == "" {
		s.TLS.Mode = "selfsigned"
	}
	if len(s.TLS.Names) == 0 {
		s.TLS.Names = append([]string{}, cfg.TLS.SelfSignedNames...)
	}
	if s.TLS.ACME.Challenge == "" {
		s.TLS.ACME.Challenge = "http-01"
	}
	for i := range s.Zones {
		zones.Normalize(&s.Zones[i], time.Now().UTC())
	}
}

// background : rotations DNSSEC et re-signature, renouvellement ACME.
func background(ctx context.Context, log *slog.Logger, a *api.API, zm *zones.Manager, store *state.Store, tm *tlsutil.Manager) {
	dnssec := time.NewTicker(10 * time.Minute)
	certs := time.NewTicker(6 * time.Hour)
	keys := time.NewTicker(6 * time.Hour)
	defer keys.Stop()
	defer dnssec.Stop()
	defer certs.Stop()
	renew := func() {
		if store.Get().TLS.Mode != "acme" || tm.Locked() || !tm.NeedsRenewal(time.Now()) {
			return
		}
		rctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		if err := a.IssueCertificate(rctx, "système"); err != nil {
			log.Error("renouvellement ACME", "err", err)
		}
	}
	first := time.After(time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-first:
			a.DNSSECTick(ctx)
			renew()
			if err := a.KeyMaintenance(ctx); err != nil {
				log.Error("rotation planifiée de la KEK", "err", err)
			}
		case <-dnssec.C:
			a.DNSSECTick(ctx)
			if zm.NeedsResign() {
				if err := zm.Load(store.Get().Zones); err != nil {
					log.Error("re-signature DNSSEC", "err", err)
				}
			}
		case <-certs.C:
			renew()
		case <-keys.C:
			// Rotation planifiée de la KEK du keystore logiciel.
			if err := a.KeyMaintenance(ctx); err != nil {
				log.Error("rotation planifiée de la KEK", "err", err)
			}
		}
	}
}

func defaultState(cfg *config.Config, adminPass string) state.State {
	st := state.State{
		Settings: state.Settings{
			BlockingEnabled: true, BlockingMode: cfg.Defaults.BlockingMode, LogMode: cfg.Defaults.LogMode,
			RetentionDays: cfg.Defaults.RetentionDays, ClientIDs: cfg.Defaults.ClientIDs,
			BlockCNAMECloak: true, RebindProtect: true, BlockDoHCanary: true,
		},
		Admin: state.Admin{Username: "admin", PasswordHash: api.HashPassword(adminPass)},
	}
	lists := cfg.Defaults.Lists
	if len(lists) == 0 {
		st.Lists = []state.List{
			{ID: "adguard-dns", Name: "AdGuard DNS filter", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", Enabled: true},
			{ID: "stevenblack", Name: "StevenBlack hosts (unifié)", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", Enabled: true},
			{ID: "hagezi-pro", Name: "HaGeZi Multi PRO", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt", Enabled: false},
		}
	}
	for i, l := range lists {
		st.Lists = append(st.Lists, state.List{ID: fmt.Sprintf("cfg-%d", i), Name: l.Name, URL: l.URL, Allow: l.Allow, SHA256: l.SHA256, Enabled: true})
	}
	for _, z := range cfg.Defaults.Zones {
		alg := z.Algorithm
		if alg == "" {
			alg = "ECDSAP256SHA256"
		}
		st.Zones = append(st.Zones, state.Zone{Name: strings.ToLower(dns.Fqdn(z.Name)), DNSSEC: z.DNSSEC, Algorithm: alg, Records: z.Records})
	}
	return st
}
