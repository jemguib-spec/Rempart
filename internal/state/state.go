// Package state holds everything an administrator can change from the web
// interface. It is persisted as a single sealed (encrypted + authenticated)
// file, so lists, rules, local zones and the admin account cannot be read or
// tampered with on disk without the keystore.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/sealed"
)

type List struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	URL        string    `json:"url"` // http(s):// URL or local file path
	Allow      bool      `json:"allow"`
	Enabled    bool      `json:"enabled"`
	SHA256     string    `json:"sha256,omitempty"` // optional pin for static lists
	Count      int       `json:"count"`
	LastUpdate time.Time `json:"last_update"`
	LastError  string    `json:"last_error,omitempty"`
}

type Rule struct {
	Domain  string    `json:"domain"`
	Allow   bool      `json:"allow"`
	Comment string    `json:"comment,omitempty"`
	Created time.Time `json:"created"`
}

type Zone struct {
	Name      string     `json:"name"` // fqdn with trailing dot
	DNSSEC    bool       `json:"dnssec"`
	Algorithm string     `json:"algorithm"`
	Records   []string   `json:"records"` // zone-file lines relative to the zone
	Serial    uint32     `json:"serial"`
	Keys      []ZoneKey  `json:"keys,omitempty"`
	Policy    ZonePolicy `json:"policy"`
	// NextAlgorithm : algorithme visé par une rotation d'algorithme en cours
	// (RFC 6781 §4.1.4) ; vide hors rotation.
	NextAlgorithm string `json:"next_algorithm,omitempty"`
	// Dynamic : enregistrements ajoutés par mises à jour dynamiques (RFC 2136),
	// séparés de ceux de l'administrateur, qu'une mise à jour ne touche jamais.
	Dynamic  []string     `json:"dynamic"`
	Transfer ZoneTransfer `json:"transfer"`
}

// ZoneTransfer : serveurs secondaires (AXFR/IXFR, NOTIFY) et mises à jour
// dynamiques. Les deux exigent une clé TSIG en plus de l'adresse source.
type ZoneTransfer struct {
	Secondaries []string `json:"secondaries"` // IP ou IP:port (NOTIFY et transfert)
	Key         string   `json:"key"`         // clé TSIG des transferts
	UpdateKey   string   `json:"update_key"`  // clé TSIG des mises à jour ("" = refusées)
	UpdateFrom  []string `json:"update_from"` // préfixes autorisés à mettre à jour
}

// TSIGKey : clé partagée HMAC (RFC 8945). Le secret, indispensable pour
// calculer les signatures, reste dans l'état scellé et n'est montré qu'à la
// création.
type TSIGKey struct {
	Name      string    `json:"name"` // FQDN canonique
	Algorithm string    `json:"algorithm"`
	Secret    string    `json:"secret,omitempty"` // base64
	Created   time.Time `json:"created"`
	Managed   bool      `json:"managed,omitempty"` // reçue de l'instance principale
}

// SecondaryZone : zone copiée d'un serveur primaire par AXFR, servie telle
// quelle (signatures DNSSEC du primaire comprises).
type SecondaryZone struct {
	Name    string `json:"name"`
	Primary string `json:"primary"` // IP:port
	Key     string `json:"key"`     // clé TSIG
	Managed bool   `json:"managed"` // créée par la réplication
}

// RPZFeed : zone de politique de réponse (flux de menaces), reçue par AXFR
// (avec TSIG) ou téléchargée en HTTPS au format fichier de zone.
type RPZFeed struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Zone    string `json:"zone"`   // nom de la zone RPZ
	Source  string `json:"source"` // axfr | https
	Primary string `json:"primary,omitempty"`
	Key     string `json:"key,omitempty"`
	URL     string `json:"url,omitempty"`
	Enabled bool   `json:"enabled"`
	Minutes int    `json:"minutes"` // période de rafraîchissement (0 : SOA)
}

// SyslogConfig : copie du journal d'audit vers un syslog ou un SIEM.
type SyslogConfig struct {
	Enabled  bool   `json:"enabled"`
	Network  string `json:"network"` // tls | tcp | udp
	Address  string `json:"address"` // hôte:port
	CABundle string `json:"ca_bundle,omitempty"`
	Hostname string `json:"hostname,omitempty"` // champ HOSTNAME des messages
}

// Replication : synchronisation entre une instance principale et des
// répliques. La réplique lit la configuration par l'API (jeton « sync ») et
// les zones par AXFR signé TSIG.
type Replication struct {
	Role     string   `json:"role"`     // "" | primary | replica
	Replicas []string `json:"replicas"` // primaire : adresses des répliques
	Key      string   `json:"key"`      // primaire : clé TSIG des répliques
	// Réplique :
	PrimaryURL string `json:"primary_url"`
	PrimaryDNS string `json:"primary_dns"` // IP:port DNS du primaire (transferts)
	Token      string `json:"token,omitempty"`
	CABundle   string `json:"ca_bundle,omitempty"`
	// Bascule automatique (deux instances). Les champs de l'autre instance
	// (PrimaryURL, PrimaryDNS, Token, CABundle) et ceux du rôle principal
	// (Replicas, Key) sont alors gardés dans les deux rôles.
	Failover        bool   `json:"failover"`
	FailoverMinutes int    `json:"failover_minutes,omitempty"`
	Epoch           uint64 `json:"epoch"`               // incrémenté à chaque prise du rôle principal
	Acting          bool   `json:"acting,omitempty"`    // principale par intérim (après une panne)
	Preferred       bool   `json:"preferred,omitempty"` // instance principale choisie par l'administrateur
}

// ZoneKey suit une clé DNSSEC pendant tout son cycle de vie (RFC 6781 §4.1) :
// published → active → retired → supprimée (ZSK), ou
// published → ready (DS attendu chez le parent) → active → retired (KSK).
type ZoneKey struct {
	Label    string `json:"label"`
	Role     string `json:"role"`               // ksk | zsk
	State    string `json:"state"`              // published | ready | active | retired
	Imported bool   `json:"imported,omitempty"` // importée lors d'une migration vers le HSM
	// Algorithm : algorithme de la clé ; vide = celui de la zone.
	Algorithm string    `json:"algorithm,omitempty"`
	Created   time.Time `json:"created"`
	Changed   time.Time `json:"changed"` // dernière transition d'état
	DSSeen    time.Time `json:"ds_seen,omitempty"`
	DSTTL     uint32    `json:"ds_ttl,omitempty"` // TTL du DS observé chez le parent
}

// ZonePolicy règle la rotation automatique des clés d'une zone.
type ZonePolicy struct {
	AutoRollover bool `json:"auto_rollover"`
	ZSKDays      int  `json:"zsk_days"`    // 0 = rotation ZSK manuelle
	KSKDays      int  `json:"ksk_days"`    // 0 = rotation KSK manuelle
	PublishCDS   bool `json:"publish_cds"` // RFC 7344 / 8078
	// NSEC3 : preuves de non-existence hachées (RFC 5155, paramètres de la
	// RFC 9276 : SHA-1, 0 itération, sans sel, sans opt-out) ; empêche de
	// lister les noms de la zone en suivant la chaîne NSEC.
	NSEC3 bool `json:"nsec3"`
}

// Resolvers décrit la résolution des noms qui ne sont ni bloqués ni locaux.
type Resolvers struct {
	Profile   string    `json:"profile"` // perso | entreprise
	Upstreams []string  `json:"upstreams"`
	Forwards  []Forward `json:"forwards"`
	// Bootstrap : DNS en clair (IP) servant uniquement à trouver l'adresse des
	// résolveurs désignés par un nom ; vide = valeur du fichier de configuration.
	Bootstrap []string `json:"bootstrap"`
	// ExtraCAs : AC (PEM) ajoutées aux racines système pour valider les
	// résolveurs DoT/DoH internes d'une PKI d'entreprise.
	ExtraCAs string `json:"extra_cas,omitempty"`
}

// Forward envoie un domaine (et ses sous-domaines) vers des serveurs dédiés,
// typiquement les contrôleurs Active Directory d'un domaine interne.
type Forward struct {
	Domain  string   `json:"domain"`
	Servers []string `json:"servers"`
}

// TLSState décrit l'origine du certificat de l'interface, de DoT et de DoH.
type TLSState struct {
	Mode     string    `json:"mode"` // selfsigned | acme | manual
	Names    []string  `json:"names"`
	KeyLabel string    `json:"key_label"`
	ACME     ACMEState `json:"acme"`
}

// ACMEState ne contient aucun secret : la clé de compte est un objet du
// keystore et la clé HMAC d'EAB n'est utilisée qu'à l'inscription.
type ACMEState struct {
	DirectoryURL string    `json:"directory_url"`
	Email        string    `json:"email"`
	Challenge    string    `json:"challenge"` // http-01 | dns-01
	CABundle     string    `json:"ca_bundle,omitempty"`
	AccountURL   string    `json:"account_url,omitempty"`
	EABKeyID     string    `json:"eab_key_id,omitempty"`
	LastAttempt  time.Time `json:"last_attempt"`
	LastSuccess  time.Time `json:"last_success"`
	LastError    string    `json:"last_error,omitempty"`
}

// APIToken : seul le SHA-256 du jeton est conservé ; le jeton (256 bits
// aléatoires) n'est affiché qu'une fois, à sa création.
type APIToken struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Hash     string    `json:"hash"`
	Scopes   []string  `json:"scopes"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	LastUsed time.Time `json:"last_used"`
}

// Encryption allume ou éteint les écoutes chiffrées déclarées dans le fichier
// de configuration (dot.listen, doh.listen). Les adresses restent dans ce
// fichier : elles doivent correspondre aux ports publiés par le conteneur.
// Valeur zéro = actif, pour qu'un état antérieur garde DoT et DoH en service.
// Propre à chaque instance : n'est pas répliqué.
type Encryption struct {
	DoTDisabled bool `json:"dot_disabled"`
	DoHDisabled bool `json:"doh_disabled"`
	DoQDisabled bool `json:"doq_disabled"`
	// DNSCrypt : désactivé tant que l'administrateur ne l'allume pas.
	DNSCryptEnabled bool `json:"dnscrypt_enabled"`
}

type Settings struct {
	BlockingEnabled bool   `json:"blocking_enabled"`
	BlockingMode    string `json:"blocking_mode"` // zero | nxdomain | refused
	LogMode         string `json:"log_mode"`      // none | stats | full
	RetentionDays   int    `json:"retention_days"`
	ClientIDs       string `json:"client_ids"` // pseudonymize | truncate | clear
	BlockCNAMECloak bool   `json:"block_cname_cloaking"`
	RebindProtect   bool   `json:"rebind_protection"`
	BlockDoHCanary  bool   `json:"block_doh_canary"`
	Suggestions     bool   `json:"suggestions"` // analyse locale des domaines résolus
	// DNSSECValidationOff coupe la validation DNSSEC locale (active par défaut).
	DNSSECValidationOff bool `json:"dnssec_validation_off"`
	// TimeZone : fuseau IANA des plages horaires (vide = fuseau du serveur).
	TimeZone string `json:"time_zone,omitempty"`
}

// Group applique une politique de filtrage propre à un ensemble d'appareils.
// Les appareils qui n'appartiennent à aucun groupe suivent la politique
// générale (listes actives, « Ma liste », réglages).
type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Clients : adresse IP, préfixe CIDR, adresse MAC (relevée dans les baux
	// DHCP ou la table de voisinage) ou « device:<id> » (profil installé).
	Clients []string `json:"clients"`
	// Blocking : filtrage publicitaire (listes, règles, services). Le
	// contrôle parental (plages horaires, SafeSearch) reste actif sans lui.
	Blocking     bool       `json:"blocking"`
	InheritLists bool       `json:"inherit_lists"` // listes actives de la politique générale
	Lists        []string   `json:"lists"`         // listes ajoutées pour ce groupe (catégories)
	InheritRules bool       `json:"inherit_rules"` // « Ma liste » générale
	Rules        []Rule     `json:"rules"`         // règles propres, prioritaires
	Services     []string   `json:"services"`      // services bloqués en permanence
	Schedules    []Schedule `json:"schedules"`
	SafeSearch   bool       `json:"safe_search"`
	YouTube      string     `json:"youtube"` // "" | moderate | strict
	PausedUntil  time.Time  `json:"paused_until"`
}

// Schedule bloque des services, ou tout accès externe, sur une plage horaire
// hebdomadaire. Une plage dont la fin précède le début passe minuit.
type Schedule struct {
	Name     string   `json:"name"`
	Days     []int    `json:"days"`  // 0 = dimanche … 6 = samedi (jour du début)
	Start    string   `json:"start"` // HH:MM
	End      string   `json:"end"`   // HH:MM
	Services []string `json:"services"`
	BlockAll bool     `json:"block_all"` // coupure complète (sauf zones locales et exceptions)
}

// Device : appareil identifié par un jeton porté dans l'URL DoH ou le nom TLS
// DoT, pour lui appliquer sa politique hors du réseau local. Seul le SHA-256
// du jeton est conservé ; le jeton n'apparaît qu'une fois, dans le profil.
type Device struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	TokenHash string    `json:"token_hash"`
	Created   time.Time `json:"created"`
}

// DeviceName : nom et type choisis pour un appareil du réseau, désigné par
// son adresse MAC (de préférence) ou son adresse IP.
type DeviceName struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

// StaticLease réserve une adresse à un appareil et lui donne un nom.
type StaticLease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// DHCPConfig : serveur DHCPv4 facultatif (RFC 2131). Les baux dynamiques
// sont scellés dans un fichier à part, écrit à chaque attribution.
type DHCPConfig struct {
	Enabled    bool          `json:"enabled"`
	Interface  string        `json:"interface"`
	ServerIP   string        `json:"server_ip"` // adresse de Rempart sur ce réseau
	RangeStart string        `json:"range_start"`
	RangeEnd   string        `json:"range_end"`
	Netmask    string        `json:"netmask"`
	Router     string        `json:"router"`
	LeaseHours int           `json:"lease_hours"`
	Domain     string        `json:"domain"`              // noms des appareils : <nom>.<domaine>
	ExtraDNS   string        `json:"extra_dns,omitempty"` // second serveur DNS annoncé (réplique)
	Static     []StaticLease `json:"static"`
}

type Admin struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	// Double authentification TOTP (RFC 6238). Le secret n'est jamais
	// renvoyé par l'API après l'activation ; l'état est scellé sur disque.
	TOTPSecret string   `json:"totp_secret,omitempty"` // base32, 160 bits
	TOTPLast   int64    `json:"totp_last,omitempty"`   // dernier pas accepté (anti-rejeu)
	Recovery   []string `json:"recovery,omitempty"`    // SHA-256 des codes de secours restants
	// Clés d'accès WebAuthn (passkeys, clés FIDO2) : second facteur, ou
	// connexion sans mot de passe si l'authentificateur vérifie l'utilisateur.
	Passkeys     []Passkey `json:"passkeys,omitempty"`
	WebAuthnUser string    `json:"webauthn_user,omitempty"` // identifiant WebAuthn du compte (base64url)
}

// Passkey : clé publique d'une clé d'accès ; la clé privée reste dans
// l'authentificateur.
type Passkey struct {
	ID        string    `json:"id"` // identifiant de la clé (base64url)
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"` // SubjectPublicKeyInfo, base64
	Alg       int       `json:"alg"`        // algorithme COSE
	SignCount uint32    `json:"sign_count"`
	RPID      string    `json:"rp_id"`
	Synced    bool      `json:"synced,omitempty"` // passkey synchronisable (BE)
	Created   time.Time `json:"created"`
	LastUsed  time.Time `json:"last_used,omitempty"`
}

// RoleGroups associe des groupes de l'annuaire (DN LDAP) ou du fournisseur
// d'identité (rôles ou groupes Keycloak) aux rôles de Rempart :
// admin (tout), operator (filtrage, zones, TLS, sans la sécurité), read.
type RoleGroups struct {
	Admin    []string `json:"admin"`
	Operator []string `json:"operator"`
	Read     []string `json:"read"`
}

// LDAPConfig : authentification par un annuaire (OpenLDAP, Active Directory,
// FreeIPA…). Le mot de passe du compte de service n'est jamais renvoyé par l'API.
type LDAPConfig struct {
	Enabled      bool       `json:"enabled"`
	URLs         string     `json:"urls"` // ldaps://dc1:636 ldaps://dc2:636
	StartTLS     bool       `json:"starttls"`
	CABundle     string     `json:"ca_bundle,omitempty"`
	BindDN       string     `json:"bind_dn"`
	BindPassword string     `json:"bind_password,omitempty"`
	UserBase     string     `json:"user_base"`
	UserFilter   string     `json:"user_filter"`
	UserAttr     string     `json:"user_attr"`
	DisplayAttr  string     `json:"display_attr"`
	GroupAttr    string     `json:"group_attr"`
	GroupBase    string     `json:"group_base"`
	GroupFilter  string     `json:"group_filter"`
	Roles        RoleGroups `json:"roles"`
}

// OIDCConfig : connexion par un fournisseur OpenID Connect (Keycloak…).
// Le secret du client n'est jamais renvoyé par l'API.
type OIDCConfig struct {
	Enabled       bool       `json:"enabled"`
	Label         string     `json:"label"`  // texte du bouton : « Keycloak »
	Issuer        string     `json:"issuer"` // https://kc.example/realms/corp
	ClientID      string     `json:"client_id"`
	ClientSecret  string     `json:"client_secret,omitempty"`
	RedirectURL   string     `json:"redirect_url"`
	Scopes        []string   `json:"scopes"`
	CABundle      string     `json:"ca_bundle,omitempty"`
	UsernameClaim string     `json:"username_claim"` // preferred_username
	RolesClaim    string     `json:"roles_claim"`    // realm_access.roles, groups…
	RequiredACR   string     `json:"required_acr,omitempty"`
	Roles         RoleGroups `json:"roles"`
}

// Identity regroupe les sources de comptes externes. Le compte local reste
// toujours utilisable (accès de secours).
type Identity struct {
	LDAP LDAPConfig `json:"ldap"`
	OIDC OIDCConfig `json:"oidc"`
}

type State struct {
	Lists       []List          `json:"lists"`
	Rules       []Rule          `json:"rules"`
	Zones       []Zone          `json:"zones"`
	Settings    Settings        `json:"settings"`
	Admin       Admin           `json:"admin"`
	PausedUntil time.Time       `json:"paused_until"`
	Resolvers   Resolvers       `json:"resolvers"`
	TLS         TLSState        `json:"tls"`
	APITokens   []APIToken      `json:"api_tokens"`
	Dismissed   []string        `json:"dismissed"` // suggestions ignorées
	Identity    Identity        `json:"identity"`
	Groups      []Group         `json:"groups"`
	Devices     []Device        `json:"devices"`
	DHCP        DHCPConfig      `json:"dhcp"`
	TSIGKeys    []TSIGKey       `json:"tsig_keys"`
	Secondaries []SecondaryZone `json:"secondaries"`
	RPZ         []RPZFeed       `json:"rpz"`
	Syslog      SyslogConfig    `json:"syslog"`
	Replication Replication     `json:"replication"`
	Encryption  Encryption      `json:"encryption"`
	// Noms donnés aux appareils de l'inventaire (Appareils → Tous les
	// appareils). Propres à chaque instance : ils ne sont pas répliqués.
	DeviceNames []DeviceName `json:"device_names"`
}

// Store is a concurrency-safe, sealed-on-disk State.
type Store struct {
	mu   sync.RWMutex
	ks   keystore.Keystore
	path string
	st   State
	subs []func(State)
}

// Open loads the state, or initialises it with def when the file is absent.
func Open(ks keystore.Keystore, path string, def State) (*Store, bool, error) {
	s := &Store{ks: ks, path: path}
	raw, err := sealed.ReadFile(ks, path)
	if errors.Is(err, os.ErrNotExist) {
		s.st = def
		normalize(&s.st)
		return s, true, s.save()
	}
	if err != nil {
		return nil, false, errors.New("état illisible (" + err.Error() + ") : keystore différent ou fichier altéré")
	}
	if err := json.Unmarshal(raw, &s.st); err != nil {
		return nil, false, err
	}
	normalize(&s.st)
	return s, false, nil
}

func (s *Store) save() error {
	raw, err := json.Marshal(s.st)
	if err != nil {
		return err
	}
	return sealed.WriteFile(s.ks, s.path, raw)
}

// Get returns a deep copy of the state.
func (s *Store) Get() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clone(s.st)
}

// Update applies fn, persists the result and notifies subscribers.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	next := clone(s.st)
	if err := fn(&next); err != nil {
		s.mu.Unlock()
		return err
	}
	prev := s.st
	s.st = next
	if err := s.save(); err != nil {
		s.st = prev
		s.mu.Unlock()
		return err
	}
	subs := append([]func(State){}, s.subs...)
	cp := clone(s.st)
	s.mu.Unlock()
	for _, f := range subs {
		f(cp)
	}
	return nil
}

// Subscribe registers a callback run after each successful update.
func (s *Store) Subscribe(f func(State)) {
	s.mu.Lock()
	s.subs = append(s.subs, f)
	s.mu.Unlock()
}

func clone(st State) State {
	raw, _ := json.Marshal(st)
	var out State
	_ = json.Unmarshal(raw, &out)
	normalize(&out)
	return out
}

// normalize remplace les tranches nil par des tranches vides : encodées en
// JSON, elles donnent [] et non null, que l'interface ne sait pas parcourir.
func normalize(st *State) {
	if st.Lists == nil {
		st.Lists = []List{}
	}
	if st.Rules == nil {
		st.Rules = []Rule{}
	}
	if st.Zones == nil {
		st.Zones = []Zone{}
	}
	if st.APITokens == nil {
		st.APITokens = []APIToken{}
	}
	if st.Dismissed == nil {
		st.Dismissed = []string{}
	}
	if st.DeviceNames == nil {
		st.DeviceNames = []DeviceName{}
	}
	if st.Resolvers.Upstreams == nil {
		st.Resolvers.Upstreams = []string{}
	}
	if st.Resolvers.Bootstrap == nil {
		st.Resolvers.Bootstrap = []string{}
	}
	if st.Resolvers.Forwards == nil {
		st.Resolvers.Forwards = []Forward{}
	}
	if st.TLS.Names == nil {
		st.TLS.Names = []string{}
	}
	for _, rg := range []*RoleGroups{&st.Identity.LDAP.Roles, &st.Identity.OIDC.Roles} {
		for _, l := range []*[]string{&rg.Admin, &rg.Operator, &rg.Read} {
			if *l == nil {
				*l = []string{}
			}
		}
	}
	if st.Identity.OIDC.Scopes == nil {
		st.Identity.OIDC.Scopes = []string{}
	}
	if st.Groups == nil {
		st.Groups = []Group{}
	}
	if st.Devices == nil {
		st.Devices = []Device{}
	}
	if st.DHCP.Static == nil {
		st.DHCP.Static = []StaticLease{}
	}
	for i := range st.Groups {
		g := &st.Groups[i]
		for _, l := range []*[]string{&g.Clients, &g.Lists, &g.Services} {
			if *l == nil {
				*l = []string{}
			}
		}
		if g.Rules == nil {
			g.Rules = []Rule{}
		}
		if g.Schedules == nil {
			g.Schedules = []Schedule{}
		}
		for j := range g.Schedules {
			for _, l := range []*[]string{&g.Schedules[j].Services} {
				if *l == nil {
					*l = []string{}
				}
			}
			if g.Schedules[j].Days == nil {
				g.Schedules[j].Days = []int{}
			}
		}
	}
	for _, l := range []*[]string{&st.Replication.Replicas} {
		if *l == nil {
			*l = []string{}
		}
	}
	if st.TSIGKeys == nil {
		st.TSIGKeys = []TSIGKey{}
	}
	if st.Secondaries == nil {
		st.Secondaries = []SecondaryZone{}
	}
	if st.RPZ == nil {
		st.RPZ = []RPZFeed{}
	}
	for i := range st.Zones {
		z := &st.Zones[i]
		for _, l := range []*[]string{&z.Dynamic, &z.Transfer.Secondaries, &z.Transfer.UpdateFrom} {
			if *l == nil {
				*l = []string{}
			}
		}
	}
	for i := range st.Zones {
		if st.Zones[i].Records == nil {
			st.Zones[i].Records = []string{}
		}
	}
}
