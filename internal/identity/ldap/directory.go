// directory.go - authentification d'un utilisateur par un annuaire :
// recherche du DN avec un compte de service, liaison avec le mot de passe de
// l'utilisateur, puis lecture de ses groupes.

package ldap

import (
	"context"
	"errors"
	"strings"
	"unicode"
)

// Directory décrit un annuaire et la façon d'y trouver les utilisateurs.
type Directory struct {
	// URLs : une ou plusieurs URL séparées par des espaces, essayées dans
	// l'ordre (contrôleurs de domaine redondants).
	URLs         string
	Opts         Options // URL ignorée : prise dans URLs
	BindDN       string  // compte de service ; vide : recherche anonyme
	BindPassword string
	UserBase     string
	UserFilter   string // ex. (&(objectClass=person)(uid={user}))
	UserAttr     string // attribut du nom de connexion affiché (uid, sAMAccountName)
	DisplayAttr  string // displayName, cn…
	GroupAttr    string // memberOf (Active Directory, overlay memberof d'OpenLDAP)
	GroupBase    string
	GroupFilter  string // ex. (&(objectClass=groupOfNames)(member={dn}))
}

// User est un utilisateur authentifié.
type User struct {
	DN       string
	Username string
	Display  string
	Groups   []string // DN des groupes
}

// ErrInvalidCredentials regroupe utilisateur inconnu, ambigu et mot de passe
// refusé : l'appelant ne doit pas pouvoir les distinguer.
var ErrInvalidCredentials = errors.New("identifiants incorrects")

// ValidUsername refuse les noms vides, trop longs ou contenant des
// caractères de contrôle.
func ValidUsername(u string) bool {
	if u == "" || len(u) > 256 || strings.TrimSpace(u) != u {
		return false
	}
	for _, r := range u {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}

func (d *Directory) dial(ctx context.Context) (*Conn, error) {
	var last error = errors.New("aucune URL d'annuaire configurée")
	for _, u := range strings.Fields(d.URLs) {
		o := d.Opts
		o.URL = u
		c, err := Dial(ctx, o)
		if err == nil {
			return c, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

func (d *Directory) serviceBind(ctx context.Context, c *Conn) error {
	if d.BindDN == "" {
		return nil
	}
	if err := c.Bind(ctx, d.BindDN, d.BindPassword); err != nil {
		return errors.New("liaison du compte de service refusée : " + err.Error())
	}
	return nil
}

func (d *Directory) find(ctx context.Context, c *Conn, username string) (*User, error) {
	filter, err := Expand(d.UserFilter, map[string]string{"user": username})
	if err != nil {
		return nil, err
	}
	attrs := []string{}
	for _, a := range []string{d.UserAttr, d.DisplayAttr, d.GroupAttr} {
		if a != "" {
			attrs = append(attrs, a)
		}
	}
	es, err := c.Search(ctx, SearchRequest{Base: d.UserBase, Scope: ScopeSubtree, Filter: filter, Attrs: attrs, SizeLimit: 2})
	if err != nil {
		var re *ResultError
		if errors.As(err, &re) && re.Code == ResultSizeLimitExceeded {
			return nil, ErrInvalidCredentials // plusieurs entrées : ambigu
		}
		return nil, err
	}
	if len(es) != 1 || es[0].DN == "" {
		return nil, ErrInvalidCredentials
	}
	e := es[0]
	u := &User{DN: e.DN, Username: username, Display: e.Get(d.DisplayAttr)}
	if d.UserAttr != "" && e.Get(d.UserAttr) != "" {
		u.Username = e.Get(d.UserAttr)
	}
	if d.GroupAttr != "" {
		u.Groups = append(u.Groups, e.Attrs[strings.ToLower(d.GroupAttr)]...)
	}
	return u, nil
}

func (d *Directory) groups(ctx context.Context, c *Conn, u *User) error {
	if d.GroupFilter == "" {
		return nil
	}
	filter, err := Expand(d.GroupFilter, map[string]string{"dn": u.DN, "user": u.Username})
	if err != nil {
		return err
	}
	base := d.GroupBase
	if base == "" {
		base = d.UserBase
	}
	es, err := c.Search(ctx, SearchRequest{Base: base, Scope: ScopeSubtree, Filter: filter, SizeLimit: 2000})
	if err != nil {
		return errors.New("recherche des groupes : " + err.Error())
	}
	for _, e := range es {
		u.Groups = append(u.Groups, e.DN)
	}
	return nil
}

// Authenticate vérifie le mot de passe d'un utilisateur et renvoie son
// identité et ses groupes.
func (d *Directory) Authenticate(ctx context.Context, username, password string) (*User, error) {
	if !ValidUsername(username) || password == "" {
		return nil, ErrInvalidCredentials
	}
	c, err := d.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if err := d.serviceBind(ctx, c); err != nil {
		return nil, err
	}
	u, err := d.find(ctx, c, username)
	if err != nil {
		return nil, err
	}
	if err := c.Bind(ctx, u.DN, password); err != nil {
		if IsInvalidCredentials(err) {
			return nil, ErrInvalidCredentials
		}
		var re *ResultError
		if errors.As(err, &re) {
			// Compte verrouillé, expiré… : refus, sans détailler à l'utilisateur.
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if d.GroupFilter != "" {
		// Les groupes sont lus avec le compte de service : l'utilisateur n'a
		// pas forcément le droit de les parcourir.
		if err := d.serviceBind(ctx, c); err != nil {
			return nil, err
		}
		if err := d.groups(ctx, c, u); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// Lookup recherche un utilisateur sans vérifier de mot de passe (test de la
// configuration depuis l'interface).
func (d *Directory) Lookup(ctx context.Context, username string) (*User, error) {
	c, err := d.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if err := d.serviceBind(ctx, c); err != nil {
		return nil, err
	}
	if username == "" {
		return nil, nil
	}
	if !ValidUsername(username) {
		return nil, errors.New("nom d'utilisateur invalide")
	}
	u, err := d.find(ctx, c, username)
	if errors.Is(err, ErrInvalidCredentials) {
		return nil, errors.New("utilisateur introuvable (ou plusieurs entrées correspondent)")
	}
	if err != nil {
		return nil, err
	}
	return u, d.groups(ctx, c, u)
}

// NormalizeDN met un DN sous une forme comparable : minuscules, espaces
// autour des séparateurs retirés. Suffisant pour comparer les DN de groupes
// saisis par un administrateur à ceux renvoyés par l'annuaire.
func NormalizeDN(dn string) string {
	parts := splitDN(dn)
	for i, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if ok {
			p = strings.TrimSpace(k) + "=" + strings.TrimSpace(v)
		}
		parts[i] = strings.ToLower(strings.TrimSpace(p))
	}
	return strings.Join(parts, ",")
}

// splitDN découpe sur les virgules non échappées.
func splitDN(dn string) []string {
	var out []string
	var cur strings.Builder
	esc := false
	for _, r := range dn {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			cur.WriteRune(r)
			esc = true
		case r == ',' || r == ';':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, cur.String())
}
