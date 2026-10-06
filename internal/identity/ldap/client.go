// Package ldap est un client LDAPv3 minimal (RFC 4511) pour authentifier les
// administrateurs de Rempart auprès d'un annuaire (OpenLDAP, Active Directory,
// FreeIPA, 389-DS…) : liaison simple, recherche, StartTLS. Il n'a aucune
// dépendance externe et refuse toute liaison par mot de passe hors TLS.
package ldap

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Codes de résultat utiles (RFC 4511 annexe A).
const (
	ResultSuccess            = 0
	ResultSizeLimitExceeded  = 4
	ResultInvalidCredentials = 49
)

// Portées de recherche.
const (
	ScopeBase    = 0
	ScopeOne     = 1
	ScopeSubtree = 2
)

// Options de connexion.
type Options struct {
	// URL : ldaps://hôte[:636] ou ldap://hôte[:389] (StartTLS obligatoire).
	URL      string
	StartTLS bool
	RootCAs  *x509.CertPool // nil : racines du système
	Timeout  time.Duration  // par opération (défaut 10 s)
}

// ResultError est une réponse d'échec de l'annuaire.
type ResultError struct {
	Code    int
	Message string
}

func (e *ResultError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("annuaire : code %d (%s)", e.Code, e.Message)
	}
	return fmt.Sprintf("annuaire : code %d", e.Code)
}

// IsInvalidCredentials indique un mot de passe refusé par l'annuaire.
func IsInvalidCredentials(err error) bool {
	var re *ResultError
	return errors.As(err, &re) && re.Code == ResultInvalidCredentials
}

// ErrEmptyPassword : une liaison simple avec un mot de passe vide est une
// liaison « non authentifiée » (RFC 4513 §5.1.2) que certains annuaires
// acceptent ; elle n'est jamais envoyée.
var ErrEmptyPassword = errors.New("mot de passe vide refusé")

// Conn est une connexion à un annuaire. Elle n'est pas sûre pour un usage
// concurrent : une opération à la fois.
type Conn struct {
	nc      net.Conn
	r       *bufio.Reader
	msgID   int64
	timeout time.Duration
}

// ParseURL valide une URL d'annuaire et renvoie l'adresse et le mode TLS.
func ParseURL(raw string, startTLS bool) (addr, host string, implicitTLS bool, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return "", "", false, errors.New("URL d'annuaire invalide (ldaps://hôte:636 ou ldap://hôte:389)")
	}
	host = u.Hostname()
	port := u.Port()
	switch u.Scheme {
	case "ldaps":
		implicitTLS = true
		if port == "" {
			port = "636"
		}
	case "ldap":
		if !startTLS {
			return "", "", false, errors.New("ldap:// sans StartTLS enverrait les mots de passe en clair : utilisez ldaps:// ou activez StartTLS")
		}
		if port == "" {
			port = "389"
		}
	default:
		return "", "", false, errors.New("schéma d'URL inconnu (ldaps:// ou ldap://)")
	}
	return net.JoinHostPort(host, port), host, implicitTLS, nil
}

// Dial ouvre la connexion et établit TLS (implicite ou StartTLS). Le
// certificat du serveur est toujours vérifié.
func Dial(ctx context.Context, o Options) (*Conn, error) {
	addr, host, implicit, err := ParseURL(o.URL, o.StartTLS)
	if err != nil {
		return nil, err
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	tc := &tls.Config{ServerName: host, RootCAs: o.RootCAs, MinVersion: tls.VersionTLS12}
	d := &net.Dialer{Timeout: o.Timeout}
	var nc net.Conn
	if implicit {
		nc, err = (&tls.Dialer{NetDialer: d, Config: tc}).DialContext(ctx, "tcp", addr)
	} else {
		nc, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("connexion à l'annuaire %s : %w", addr, err)
	}
	c := &Conn{nc: nc, r: bufio.NewReader(nc), timeout: o.Timeout}
	if !implicit {
		if err := c.startTLS(ctx, tc); err != nil {
			nc.Close()
			return nil, err
		}
	}
	return c, nil
}

// Close envoie UnbindRequest puis ferme la connexion.
func (c *Conn) Close() error {
	c.msgID++
	_ = c.nc.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = c.nc.Write(seq(tagSequence, encInt(tagInteger, c.msgID), tlv(classApplication|2, nil)))
	return c.nc.Close()
}

func (c *Conn) deadline(ctx context.Context) {
	dl := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	_ = c.nc.SetDeadline(dl)
}

// send écrit une requête et renvoie son identifiant.
func (c *Conn) send(ctx context.Context, op []byte) (int64, error) {
	c.msgID++
	c.deadline(ctx)
	_, err := c.nc.Write(seq(tagSequence, encInt(tagInteger, c.msgID), op))
	return c.msgID, err
}

// recv lit le prochain message destiné à id et renvoie son protocolOp.
func (c *Conn) recv(ctx context.Context, id int64) (*element, error) {
	for {
		c.deadline(ctx)
		m, err := readMessage(c.r)
		if err != nil {
			return nil, fmt.Errorf("lecture de la réponse de l'annuaire : %w", err)
		}
		if m.tag != tagSequence || len(m.children) < 2 {
			return nil, errBER
		}
		mid, err := m.children[0].int()
		if err != nil {
			return nil, err
		}
		op := m.children[1]
		if mid == 0 { // notification de déconnexion (RFC 4511 §4.4.1)
			return nil, errors.New("l'annuaire a fermé la connexion")
		}
		if mid != id {
			return nil, errBER
		}
		return op, nil
	}
}

// result décode un LDAPResult.
func result(op *element) error {
	if !op.constructed() || len(op.children) < 3 {
		return errBER
	}
	code, err := op.children[0].int()
	if err != nil {
		return err
	}
	if code != ResultSuccess {
		msg := op.children[2].str()
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return &ResultError{Code: int(code), Message: strings.Map(printable, msg)}
	}
	return nil
}

func printable(r rune) rune {
	if r < 0x20 || r == 0x7f {
		return -1
	}
	return r
}

func (c *Conn) startTLS(ctx context.Context, tc *tls.Config) error {
	id, err := c.send(ctx, seq(classApplication|constructed|23, encStr(classContext|0, "1.3.6.1.4.1.1466.20037")))
	if err != nil {
		return err
	}
	op, err := c.recv(ctx, id)
	if err != nil {
		return err
	}
	if op.tag != classApplication|constructed|24 {
		return errBER
	}
	if err := result(op); err != nil {
		return fmt.Errorf("StartTLS refusé : %w", err)
	}
	if c.r.Buffered() > 0 { // données en clair glissées avant TLS : refus
		return errors.New("StartTLS : données inattendues avant la négociation TLS")
	}
	tconn := tls.Client(c.nc, tc)
	c.deadline(ctx)
	if err := tconn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("StartTLS : %w", err)
	}
	c.nc = tconn
	c.r = bufio.NewReader(tconn)
	return nil
}

// Bind effectue une liaison simple. Un mot de passe vide est refusé.
func (c *Conn) Bind(ctx context.Context, dn, password string) error {
	if password == "" {
		return ErrEmptyPassword
	}
	id, err := c.send(ctx, seq(classApplication|constructed|0,
		encInt(tagInteger, 3), encStr(tagOctetString, dn), encStr(classContext|0, password)))
	if err != nil {
		return err
	}
	op, err := c.recv(ctx, id)
	if err != nil {
		return err
	}
	if op.tag != classApplication|constructed|1 {
		return errBER
	}
	return result(op)
}

// Entry est une entrée renvoyée par une recherche.
type Entry struct {
	DN    string
	Attrs map[string][]string // noms d'attributs en minuscules
}

// Get renvoie la première valeur d'un attribut.
func (e Entry) Get(name string) string {
	if v := e.Attrs[strings.ToLower(name)]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// SearchRequest décrit une recherche.
type SearchRequest struct {
	Base      string
	Scope     int
	Filter    string // forme texte, déjà échappée
	Attrs     []string
	SizeLimit int
}

// Search exécute une recherche (références ignorées).
func (c *Conn) Search(ctx context.Context, req SearchRequest) ([]Entry, error) {
	f, err := CompileFilter(req.Filter)
	if err != nil {
		return nil, err
	}
	var attrs [][]byte
	for _, a := range req.Attrs {
		attrs = append(attrs, encStr(tagOctetString, a))
	}
	if len(attrs) == 0 {
		attrs = append(attrs, encStr(tagOctetString, "1.1")) // aucun attribut
	}
	id, err := c.send(ctx, seq(classApplication|constructed|3,
		encStr(tagOctetString, req.Base),
		encInt(tagEnumerated, int64(req.Scope)),
		encInt(tagEnumerated, 0), // derefAliases : jamais
		encInt(tagInteger, int64(req.SizeLimit)),
		encInt(tagInteger, int64(c.timeout/time.Second)),
		encBool(tagBoolean, false),
		f,
		seq(tagSequence, attrs...)))
	if err != nil {
		return nil, err
	}
	var out []Entry
	for {
		op, err := c.recv(ctx, id)
		if err != nil {
			return nil, err
		}
		switch op.tag {
		case classApplication | constructed | 4: // SearchResultEntry
			e, err := parseEntry(op)
			if err != nil {
				return nil, err
			}
			out = append(out, e)
			if len(out) > 10000 {
				return nil, errors.New("recherche : trop d'entrées")
			}
		case classApplication | constructed | 19: // référence : ignorée
		case classApplication | constructed | 5: // SearchResultDone
			if err := result(op); err != nil {
				var re *ResultError
				if errors.As(err, &re) && re.Code == ResultSizeLimitExceeded {
					return out, err
				}
				return nil, err
			}
			return out, nil
		default:
			return nil, errBER
		}
	}
}

func parseEntry(op *element) (Entry, error) {
	if len(op.children) != 2 || op.children[1].tag != tagSequence {
		return Entry{}, errBER
	}
	e := Entry{DN: op.children[0].str(), Attrs: map[string][]string{}}
	for _, a := range op.children[1].children {
		if a.tag != tagSequence || len(a.children) != 2 || a.children[1].tag != tagSet {
			return Entry{}, errBER
		}
		name := strings.ToLower(a.children[0].str())
		for _, v := range a.children[1].children {
			if v.constructed() {
				return Entry{}, errBER
			}
			e.Attrs[name] = append(e.Attrs[name], v.str())
		}
	}
	return e, nil
}
