// Package tlsutil gère le certificat de l'interface, de DoT et de DoH.
//
// La clé privée est une clé du keystore : avec un HSM, la signature du
// handshake TLS est calculée dans le HSM et la clé ne peut pas être volée sur
// le disque ou en mémoire. Le certificat peut être auto-signé, obtenu par
// ACME auprès de n'importe quelle AC compatible (Let's Encrypt, EJBCA,
// EverTrust Horizon…) ou importé après signature d'une CSR par une PKI. Il
// est remplacé à chaud, sans redémarrage.
package tlsutil

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rempart-dns/rempart/internal/keystore"
)

// Options mirrors the tls section of the configuration.
type Options struct {
	CertFile, KeyFile, KeyLabel string
	SelfSignedNames             []string
	DataDir                     string
}

// Info décrit le certificat en service (affiché dans l'interface).
type Info struct {
	Mode        string    `json:"mode"`   // selfsigned | acme | manual | file
	Source      string    `json:"source"` // emplacement de la clé privée
	SelfSigned  bool      `json:"self_signed"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Names       []string  `json:"names"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`  // SHA-256 de la clé publique (abrégé)
	CertSHA256  string    `json:"cert_sha256"`  // SHA-256 du certificat
	ChainLength int       `json:"chain_length"` // certificats envoyés aux clients
	KeyLabel    string    `json:"key_label,omitempty"`
}

// Manager détient le certificat courant.
type Manager struct {
	ks       keystore.Keystore
	opts     Options
	log      *slog.Logger
	fileMode bool

	cur  atomic.Pointer[tls.Certificate]
	info atomic.Pointer[Info]

	issue  sync.Mutex // une seule émission ACME à la fois
	http01 sync.Map   // jeton → autorisation de clé (défi http-01)
}

// certPath : chaîne obtenue par ACME ou importée (données publiques).
func (m *Manager) certPath() string { return filepath.Join(m.opts.DataDir, "tls-cert.pem") }

// New charge le certificat existant ou crée un certificat auto-signé.
// mode et names viennent de l'état (choix faits dans l'interface).
func New(ks keystore.Keystore, o Options, mode string, names []string, log *slog.Logger) (*Manager, error) {
	m := &Manager{ks: ks, opts: o, log: log}
	if len(names) > 0 {
		m.opts.SelfSignedNames = names
	}
	if o.KeyFile != "" { // clé classique sur disque, imposée par la configuration
		cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return nil, err
		}
		m.fileMode = true
		return m, m.set(&cert, "file", "fichier "+o.KeyFile, "")
	}
	signer, err := ks.Signer(o.KeyLabel, keystore.ECDSAP256, true)
	if err != nil {
		return nil, fmt.Errorf("clé TLS %q: %w", o.KeyLabel, err)
	}
	// Priorité : chaîne imposée par la configuration, puis chaîne obtenue ou
	// importée depuis l'interface, sinon certificat auto-signé.
	if o.CertFile != "" {
		der, err := readChain(o.CertFile)
		if err != nil {
			return nil, err
		}
		m.fileMode = true
		return m, m.install(der, signer, "file")
	}
	if mode == "acme" || mode == "manual" {
		if der, err := readChain(m.certPath()); err == nil {
			if err := m.install(der, signer, mode); err == nil {
				return m, nil
			} else {
				log.Warn("certificat enregistré inutilisable, retour à l'auto-signé", "err", err)
			}
		}
	}
	return m, m.SelfSigned(false)
}

// Locked indique que le certificat est imposé par le fichier de
// configuration (tls.cert_file / key_file) et non modifiable depuis l'interface.
func (m *Manager) Locked() bool { return m.fileMode }

// Config renvoie la configuration TLS ; le certificat est lu à chaque
// handshake, ce qui permet de le remplacer à chaud.
func (m *Manager) Config() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1", "dot"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return m.cur.Load(), nil
		},
	}
}

// Leaf renvoie le certificat feuille en service.
func (m *Manager) Leaf() *x509.Certificate { return m.cur.Load().Leaf }

// Info renvoie la description du certificat courant.
func (m *Manager) Info() Info { return *m.info.Load() }

// SigningIdentity renvoie la chaîne en service et sa clé privée (keystore,
// HSM compris, ou fichier en mode tls.key_file), pour signer un profil.
func (m *Manager) SigningIdentity() ([][]byte, crypto.Signer, error) {
	c := m.cur.Load()
	if c == nil {
		return nil, nil, errors.New("aucun certificat en service")
	}
	s, ok := c.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("clé du certificat inutilisable pour signer")
	}
	return c.Certificate, s, nil
}

// Signer renvoie la clé TLS du keystore.
func (m *Manager) Signer() (crypto.Signer, error) {
	return m.ks.Signer(m.opts.KeyLabel, keystore.ECDSAP256, true)
}

func (m *Manager) set(c *tls.Certificate, mode, source, label string) error {
	leaf := c.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return err
		}
		c.Leaf = leaf
	}
	sum := sha256.Sum256(leaf.Raw)
	names := append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	info := &Info{Mode: mode, Source: source, SelfSigned: bytes.Equal(leaf.RawIssuer, leaf.RawSubject) && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil,
		Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(), Names: names,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Fingerprint: keystore.Fingerprint(leaf.PublicKey),
		CertSHA256: hex.EncodeToString(sum[:]), ChainLength: len(c.Certificate), KeyLabel: label}
	m.cur.Store(c)
	m.info.Store(info)
	return nil
}

// install vérifie puis met en service une chaîne pour la clé du keystore.
func (m *Manager) install(der [][]byte, signer crypto.Signer, mode string) error {
	chain := make([]*x509.Certificate, 0, len(der))
	for i, d := range der {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return fmt.Errorf("certificat %d illisible: %w", i+1, err)
		}
		chain = append(chain, c)
	}
	leaf := chain[0]
	if keystore.Fingerprint(leaf.PublicKey) != keystore.Fingerprint(signer.Public()) {
		return errors.New("le certificat ne correspond pas à la clé TLS du keystore")
	}
	now := time.Now()
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("certificat expiré le %s", leaf.NotAfter.Format(time.DateOnly))
	}
	if now.Add(5 * time.Minute).Before(leaf.NotBefore) {
		return fmt.Errorf("certificat valide seulement à partir du %s", leaf.NotBefore.Format(time.DateTime))
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && len(leaf.ExtKeyUsage) > 0 {
		return errors.New("le certificat n'autorise pas l'usage serverAuth")
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("le certificat n'autorise pas digitalSignature (nécessaire à une clé ECDSA en TLS)")
	}
	// Chaque certificat doit être signé par le suivant : une chaîne dans le
	// désordre ou incomplète ferait échouer les clients.
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return fmt.Errorf("chaîne invalide : le certificat %d n'est pas signé par le certificat %d (%v)", i+1, i+2, err)
		}
	}
	return m.set(&tls.Certificate{Certificate: der, PrivateKey: signer, Leaf: leaf}, mode, "keystore ("+m.ks.Backend()+")", m.opts.KeyLabel)
}

// Install remplace le certificat par une chaîne PEM (feuille d'abord) pour
// la clé TLS du keystore, et l'enregistre pour les redémarrages.
func (m *Manager) Install(chainPEM []byte, mode string) (Info, error) {
	if m.fileMode {
		return Info{}, errors.New("certificat imposé par le fichier de configuration (tls.cert_file)")
	}
	der, err := parseChain(chainPEM)
	if err != nil {
		return Info{}, err
	}
	signer, err := m.Signer()
	if err != nil {
		return Info{}, err
	}
	if err := m.install(der, signer, mode); err != nil {
		return Info{}, err
	}
	if err := writeChain(m.certPath(), der); err != nil {
		return Info{}, err
	}
	return m.Info(), nil
}

// SelfSigned revient à un certificat auto-signé ; force le régénère même si
// l'ancien est encore valide.
func (m *Manager) SelfSigned(force bool) error {
	if m.fileMode {
		return errors.New("certificat imposé par le fichier de configuration (tls.cert_file)")
	}
	signer, err := m.Signer()
	if err != nil {
		return err
	}
	der, err := selfSignedFor(signer, m.opts, force)
	if err != nil {
		return err
	}
	_ = os.Remove(m.certPath())
	return m.install(der, signer, "selfsigned")
}

// CSR produit une demande de certificat PKCS#10 signée par la clé du
// keystore, à faire signer par n'importe quelle PKI.
func (m *Manager) CSR(names []string) ([]byte, error) {
	if len(names) == 0 {
		return nil, errors.New("au moins un nom est nécessaire")
	}
	signer, err := m.Signer()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
}

// NeedsRenewal : moins d'un tiers de la durée de validité restant.
func (m *Manager) NeedsRenewal(now time.Time) bool {
	i := m.Info()
	life := i.NotAfter.Sub(i.NotBefore)
	return now.After(i.NotAfter.Add(-life / 3))
}

func parseChain(raw []byte) ([][]byte, error) {
	var der [][]byte
	for {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		if b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE":
			der = append(der, b.Bytes)
		case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
			// Une clé privée n'a rien à faire ici : la clé TLS reste dans le keystore.
			return nil, errors.New("le fichier contient une clé privée : n'envoyez que la chaîne de certificats")
		}
	}
	if len(der) == 0 {
		return nil, errors.New("aucun certificat PEM trouvé")
	}
	return der, nil
}

func readChain(path string) ([][]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	der, err := parseChain(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return der, nil
}

func writeChain(path string, der [][]byte) error {
	var buf bytes.Buffer
	for _, d := range der {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: d})
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// selfSignedFor reuses a stored self-signed certificate when it still
// matches the key and names and is valid for at least 30 days; otherwise it
// creates one.
func selfSignedFor(signer crypto.Signer, o Options, force bool) ([][]byte, error) {
	path := filepath.Join(o.DataDir, "tls-selfsigned.pem")
	if der, err := readChain(path); err == nil && !force {
		if c, err := x509.ParseCertificate(der[0]); err == nil &&
			time.Until(c.NotAfter) > 30*24*time.Hour &&
			keystore.Fingerprint(c.PublicKey) == keystore.Fingerprint(signer.Public()) &&
			sameNames(c, o.SelfSignedNames) {
			return der, nil
		}
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: o.SelfSignedNames[0], Organization: []string{"Rempart DNS"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, n := range o.SelfSignedNames {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return nil, err
	}
	_ = writeChain(path, [][]byte{der})
	return [][]byte{der}, nil
}

func sameNames(c *x509.Certificate, names []string) bool {
	have := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		have = append(have, ip.String())
	}
	want := make([]string, 0, len(names))
	for _, n := range names {
		want = append(want, strings.ToLower(n))
	}
	slices.Sort(have)
	slices.Sort(want)
	return slices.Equal(have, want)
}
