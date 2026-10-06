// rollover.go - cycle de vie et rotation des clés DNSSEC (ZSK pré-publication, KSK double signature).
// Fonctions pures sur state.Zone ; destruction des clés laissée à l'appelant.
// Rempart ; RFC 6781, 7344, 7583, 8078.

package zones

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/state"
)

// États d'une clé DNSSEC.
const (
	StatePublished = "published" // dans le DNSKEY, ne signe pas encore la zone
	StateReady     = "ready"     // KSK propagée : son DS peut être publié chez le parent
	StateActive    = "active"    // signe (ZSK : la zone ; KSK : le DNSKEY)
	StateRetired   = "retired"   // encore publiée le temps que les caches expirent
	// Rotation d'algorithme (RFC 6781 §4.1.4) : une clé peut signer sans
	// figurer dans le DNSKEY, avant sa publication ou après son retrait.
	StatePresign  = "presign"  // nouvel algorithme : signe, pas encore publiée
	StatePostsign = "postsign" // ancien algorithme : retirée du DNSKEY, signe encore
)

// Timing regroupe les délais de rotation (RFC 6781 §4.1 et RFC 7583).
type Timing struct {
	// Propagation : marge ajoutée à chaque TTL pour la propagation et les
	// horloges décalées.
	Propagation time.Duration
	// DSDefaultTTL : TTL supposé du DS chez le parent quand il n'a pas pu
	// être observé (confirmation manuelle, zone interne).
	DSDefaultTTL time.Duration
}

// DefaultTiming : une heure de marge, DS supposé à 24 h (TTL courant des TLD).
var DefaultTiming = Timing{Propagation: time.Hour, DSDefaultTTL: 24 * time.Hour}

// dnskeyTTL est le TTL des DNSKEY générés par Rempart (voir DNSKEYFromSigner).
const dnskeyTTL = time.Hour

// Normalize inscrit explicitement les clés historiques d'une zone signée,
// pour que leur cycle de vie puisse ensuite être suivi.
func Normalize(sz *state.Zone, now time.Time) bool {
	if !sz.DNSSEC || len(sz.Keys) > 0 {
		return false
	}
	sz.Keys = EffectiveKeys(*sz)
	for i := range sz.Keys {
		sz.Keys[i].Created, sz.Keys[i].Changed = now, now
	}
	if sz.Policy.ZSKDays == 0 && sz.Policy.KSKDays == 0 && !sz.Policy.AutoRollover {
		sz.Policy = DefaultPolicy()
	}
	return true
}

// GenerateKeys crée dans le keystore les clés d'une zone qui vient d'être
// signée pour la première fois (création, ou activation de DNSSEC).
func GenerateKeys(ks keystore.Keystore, sz state.Zone) error {
	alg, err := keystore.ParseAlgorithm(sz.Algorithm)
	if err != nil {
		return err
	}
	for _, k := range EffectiveKeys(sz) {
		if _, err := ks.Signer(k.Label, alg, true); err != nil {
			return fmt.Errorf("%s : %w", k.Label, err)
		}
	}
	return nil
}

// DefaultPolicy : ZSK renouvelée tous les 90 jours automatiquement ; la KSK
// reste manuelle car elle demande une action chez le parent, sauf si le
// parent lit les CDS. Les nouvelles zones utilisent NSEC3, pour qu'on ne
// puisse pas lister leurs noms.
func DefaultPolicy() state.ZonePolicy {
	return state.ZonePolicy{AutoRollover: true, ZSKDays: 90, KSKDays: 0, PublishCDS: true, NSEC3: true}
}

// InProgress indique si une rotation du rôle donné est en cours.
func InProgress(sz state.Zone, role string) bool {
	for _, k := range sz.Keys {
		if k.Role == role && k.State != StateActive {
			return true
		}
	}
	return false
}

// StartRollover ajoute une nouvelle clé « published » ; elle sera générée
// dans le keystore à la prochaine signature de la zone.
func StartRollover(sz *state.Zone, role string, now time.Time) (string, error) {
	if role != "ksk" && role != "zsk" {
		return "", errors.New("rôle de clé inconnu (ksk ou zsk)")
	}
	if !sz.DNSSEC {
		return "", errors.New("la zone n'est pas signée")
	}
	Normalize(sz, now)
	if sz.NextAlgorithm != "" {
		return "", errors.New("une rotation d'algorithme est en cours")
	}
	if InProgress(*sz, role) {
		return "", fmt.Errorf("une rotation de %s est déjà en cours", strings.ToUpper(role))
	}
	label := KeyLabel(dns.Fqdn(sz.Name), role) + "-" + now.UTC().Format("20060102150405")
	sz.Keys = append(sz.Keys, state.ZoneKey{Label: label, Role: role, State: StatePublished, Created: now, Changed: now})
	return label, nil
}

// StartAlgorithmRollover démarre le passage de la zone à un autre
// algorithme (RFC 6781 §4.1.4, méthode prudente) :
//
//  1. une KSK et une ZSK du nouvel algorithme signent la zone sans être
//     publiées (« presign »), le temps que les caches reçoivent ces signatures ;
//  2. elles sont publiées dans le DNSKEY ; la nouvelle KSK devient prête, son
//     DS doit remplacer l'ancien chez le parent (CDS si activé) ;
//  3. une fois le DS constaté et l'ancien expiré des caches, les anciennes
//     clés quittent le DNSKEY mais signent encore (« postsign ») ;
//  4. puis leurs signatures disparaissent et les clés sont détruites.
//
// À chaque étape, chaque RRset est signé par chaque algorithme du DNSKEY
// (RFC 4035 §2.2).
func StartAlgorithmRollover(sz *state.Zone, alg string, now time.Time) ([]string, error) {
	if !sz.DNSSEC {
		return nil, errors.New("la zone n'est pas signée")
	}
	to, err := keystore.ParseAlgorithm(alg)
	if err != nil {
		return nil, err
	}
	from, err := keystore.ParseAlgorithm(sz.Algorithm)
	if err != nil {
		return nil, err
	}
	if to == from {
		return nil, fmt.Errorf("la zone est déjà en %s", to)
	}
	Normalize(sz, now)
	if sz.NextAlgorithm != "" {
		return nil, errors.New("une rotation d'algorithme est déjà en cours")
	}
	if InProgress(*sz, "ksk") || InProgress(*sz, "zsk") {
		return nil, errors.New("terminez d'abord la rotation de clé en cours")
	}
	// L'algorithme de chaque clé existante est désormais explicite.
	for i := range sz.Keys {
		if sz.Keys[i].Algorithm == "" {
			sz.Keys[i].Algorithm = string(from)
		}
	}
	sz.Algorithm = string(from)
	sz.NextAlgorithm = string(to)
	var labels []string
	for _, role := range []string{"ksk", "zsk"} {
		label := KeyLabel(dns.Fqdn(sz.Name), role) + "-" + strings.ToLower(string(to)) + "-" + now.UTC().Format("20060102150405")
		sz.Keys = append(sz.Keys, state.ZoneKey{Label: label, Role: role, State: StatePresign, Algorithm: string(to), Created: now, Changed: now})
		labels = append(labels, label)
	}
	return labels, nil
}

// ConfirmDS enregistre que le DS des KSK prêtes est publié chez le parent
// (constat automatique ou déclaration de l'administrateur).
func ConfirmDS(sz *state.Zone, now time.Time, ttl uint32) bool {
	changed := false
	for i := range sz.Keys {
		k := &sz.Keys[i]
		if k.Role == "ksk" && k.State == StateReady && k.DSSeen.IsZero() {
			k.DSSeen, k.DSTTL = now, ttl
			changed = true
		}
	}
	return changed
}

// Advance fait progresser les rotations en cours et démarre celles que la
// politique impose. Il renvoie une description des transitions et les labels
// des clés à détruire dans le keystore.
//
// live, s'il n'est pas nil, contient les labels réellement publiés dans le
// DNSKEY servi : une clé n'avance pas tant qu'elle n'y figure pas (si la
// re-signature a échoué, le délai de pré-publication n'a pas couru).
func Advance(sz *state.Zone, now time.Time, maxTTL time.Duration, t Timing, live map[string]bool) (changes, destroy []string) {
	if !sz.DNSSEC {
		return nil, nil
	}
	if Normalize(sz, now) {
		changes = append(changes, "clés existantes inscrites dans le suivi de rotation")
	}
	publishWait := dnskeyTTL + t.Propagation
	zskRetireWait := max(maxTTL, dnskeyTTL) + t.Propagation
	set := func(k *state.ZoneKey, st string) {
		changes = append(changes, fmt.Sprintf("%s %s : %s → %s", strings.ToUpper(k.Role), k.Label, k.State, st))
		k.State, k.Changed = st, now
	}
	active := func(role string) *state.ZoneKey {
		for i := range sz.Keys {
			if sz.Keys[i].Role == role && sz.Keys[i].State == StateActive {
				return &sz.Keys[i]
			}
		}
		return nil
	}
	remove := map[string]bool{}
	algRoll := sz.NextAlgorithm != ""
	isNew := func(k *state.ZoneKey) bool { return algRoll && k.Algorithm == sz.NextAlgorithm }
	// Signatures du nouvel algorithme dans tous les caches : plus grand TTL
	// de la zone (et du DNSKEY) plus la marge.
	presignWait := max(maxTTL, dnskeyTTL) + t.Propagation
	for i := range sz.Keys {
		k := &sz.Keys[i]
		age := now.Sub(k.Changed)
		if live != nil && !live[k.Label] {
			if k.State == StatePublished || k.State == StatePresign {
				k.Changed = now // le délai repart de la publication effective
			}
			continue
		}
		if algRoll {
			switch {
			case k.State == StatePresign && age >= presignWait:
				if k.Role == "zsk" {
					set(k, StateActive) // publiée, signe avec l'ancienne ZSK
				} else {
					set(k, StatePublished) // puis prête, puis active sur DS
				}
				continue
			case k.Role == "ksk" && !isNew(k) && k.State == StateRetired:
				wait := max(t.DSDefaultTTL, time.Duration(k.DSTTL)*time.Second)
				if age >= wait+t.Propagation {
					// L'ancien DS a quitté les caches : les anciennes clés
					// quittent le DNSKEY mais signent encore.
					set(k, StatePostsign)
					for j := range sz.Keys {
						o := &sz.Keys[j]
						if o.Role == "zsk" && !isNew(o) && o.State == StateActive {
							set(o, StatePostsign)
						}
					}
				}
				continue
			case k.State == StatePostsign && age >= dnskeyTTL+t.Propagation:
				changes = append(changes, strings.ToUpper(k.Role)+" "+k.Label+" ("+KeyAlgorithm(*sz, *k)+") : signatures retirées, clé détruite")
				remove[k.Label] = true
				continue
			case k.Role == "zsk" && k.State == StateActive:
				continue // deux ZSK actives (une par algorithme) : rien à faire
			}
		}
		switch {
		// ZSK par pré-publication : la nouvelle clé est connue des caches
		// avant de signer ; l'ancienne reste publiée tant que des signatures
		// faites avec elle peuvent être en cache.
		case k.Role == "zsk" && k.State == StatePublished && age >= publishWait:
			if old := active("zsk"); old != nil {
				set(old, StateRetired)
			}
			set(k, StateActive)
		case k.Role == "zsk" && k.State == StateRetired && age >= zskRetireWait:
			changes = append(changes, "ZSK "+k.Label+" retirée du DNSKEY et détruite")
			remove[k.Label] = true
		// KSK par double signature : publiée, puis prête (DS à déposer),
		// active quand le DS est constaté chez le parent ; l'ancienne signe
		// encore le DNSKEY le temps que le DS précédent expire des caches.
		case k.Role == "ksk" && k.State == StatePublished && age >= publishWait:
			set(k, StateReady)
		case k.Role == "ksk" && k.State == StateReady && !k.DSSeen.IsZero():
			if old := active("ksk"); old != nil {
				set(old, StateRetired)
				old.DSTTL = k.DSTTL
			}
			set(k, StateActive)
		case k.Role == "ksk" && k.State == StateRetired:
			// Le TTL observé via un résolveur est le TTL restant en cache, pas
			// celui du parent : on attend au moins la valeur par défaut.
			wait := max(t.DSDefaultTTL, time.Duration(k.DSTTL)*time.Second)
			if age >= wait+t.Propagation {
				changes = append(changes, "KSK "+k.Label+" retirée du DNSKEY et détruite")
				remove[k.Label] = true
			}
		}
	}
	// Les transitions modifient sz.Keys en place (l'ancienne clé active peut
	// précéder la nouvelle) ; les suppressions sont appliquées ensuite.
	keep := sz.Keys[:0]
	for _, k := range sz.Keys {
		if remove[k.Label] {
			destroy = append(destroy, k.Label)
			continue
		}
		keep = append(keep, k)
	}
	sz.Keys = keep

	if algRoll {
		old := 0
		for _, k := range sz.Keys {
			if !isNew(&k) {
				old++
			}
		}
		if old == 0 {
			changes = append(changes, "rotation d'algorithme terminée : "+sz.Algorithm+" → "+sz.NextAlgorithm)
			sz.Algorithm, sz.NextAlgorithm = sz.NextAlgorithm, ""
		}
		return changes, destroy
	}

	if sz.Policy.AutoRollover {
		for _, r := range []struct {
			role string
			days int
		}{{"zsk", sz.Policy.ZSKDays}, {"ksk", sz.Policy.KSKDays}} {
			if r.days <= 0 || InProgress(*sz, r.role) {
				continue
			}
			if a := active(r.role); a != nil && now.Sub(a.Changed) >= time.Duration(r.days)*24*time.Hour {
				if label, err := StartRollover(sz, r.role, now); err == nil {
					changes = append(changes, "rotation automatique : nouvelle "+strings.ToUpper(r.role)+" "+label)
				}
			}
		}
	}
	return changes, destroy
}

// ReadyDS renvoie, pour chaque zone ayant une KSK prête, les DS attendus
// chez le parent (format présentation).
func ReadyDS(sz state.Zone, z *Zone) []string {
	if z == nil {
		return nil
	}
	var out []string
	for _, k := range z.Keys {
		if k.Role == "ksk" && k.State == StateReady {
			out = append(out, k.DS)
		}
	}
	return out
}
