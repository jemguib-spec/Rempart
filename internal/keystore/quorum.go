// quorum.go - quorum M-sur-N du keystore logiciel : cérémonie, approbations, rotation, déverrouillage.
// Entrées : phrases de passe des dépositaires ; sorties : parts de Shamir vérifiées, master.json réécrit.
// Rempart ; une opération sensible exige M parts qui reconstituent exactement la clé racine en service.

package keystore

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rempart-dns/rempart/internal/secmem"
)

const (
	MaxCustodians    = 16
	MinCustodianPass = 12
)

// CustodianInfo et QuorumStatus décrivent le keystore pour l'affichage
// (aucun secret).
type CustodianInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Added       time.Time `json:"added"`
	TerminalSet bool      `json:"terminal_set"`
}

type GenerationInfo struct {
	Gen     uint32     `json:"gen"`
	Created time.Time  `json:"created"`
	Retired *time.Time `json:"retired,omitempty"`
	Current bool       `json:"current"`
	Legacy  bool       `json:"legacy"` // génération 0 : ancienne clé maître dérivée de la phrase de passe
}

type QuorumStatus struct {
	Mode          string           `json:"mode"`
	Threshold     int              `json:"threshold"`
	Custodians    []CustodianInfo  `json:"custodians"`
	Since         time.Time        `json:"since,omitempty"`
	ServerPass    string           `json:"server_passphrase"` // "argon2id", "none" ou "" (absente)
	Generations   []GenerationInfo `json:"generations"`
	Current       uint32           `json:"current"`
	RotateDays    int              `json:"rotate_days"`
	NextRotation  *time.Time       `json:"next_rotation,omitempty"`
	RootID        string           `json:"root_id"`
	RootCreated   time.Time        `json:"root_created"`
	ArgonParams   string           `json:"argon2id"`
	QuorumEnabled bool             `json:"quorum_enabled"`
	TerminalOnly  bool             `json:"terminal_only"`
	rootID        string
}

func (s *Software) QuorumStatus() QuorumStatus {
	s.kmu.RLock()
	defer s.kmu.RUnlock()
	b := s.body
	st := QuorumStatus{rootID: b.RootID, Mode: b.Mode, Current: b.Current, RotateDays: b.RotateDays, RootID: b.RootID[:8], RootCreated: b.Created,
		ArgonParams: fmt.Sprintf("t=%d, m=%d Mio, p=%d", argonT, argonM/1024, argonP), Custodians: []CustodianInfo{}}
	if b.Passphrase != nil {
		st.ServerPass = b.Passphrase.KDF
	}
	if q := b.Quorum; q != nil {
		st.QuorumEnabled, st.Threshold, st.Since, st.TerminalOnly = true, q.Threshold, q.Since, q.TerminalOnly
		for _, c := range q.Custodians {
			st.Custodians = append(st.Custodians, CustodianInfo{ID: c.ID, Name: c.Name, Added: c.Added, TerminalSet: c.TerminalSet})
		}
	}
	for _, e := range b.Keyring {
		st.Generations = append(st.Generations, GenerationInfo{Gen: e.Gen, Created: e.Created, Retired: e.Retired, Current: e.Gen == b.Current, Legacy: e.Gen == 0})
		if e.Gen == b.Current && b.RotateDays > 0 {
			t := e.Created.AddDate(0, 0, b.RotateDays)
			st.NextRotation = &t
		}
	}
	sort.Slice(st.Generations, func(i, j int) bool { return st.Generations[i].Gen > st.Generations[j].Gen })
	return st
}

// ---- parts ----

var idLike = regexp.MustCompile(`^[0-9a-f]{8}$`)

// ValidCustodianName : lettres latines précomposées (é, ç…), chiffres, espace et « -_.' »,
// 1 à 64 caractères. Pas de caractère de contrôle ni de format (un NUL
// permettait de faire passer deux noms pour un seul), pas de marque
// combinante (une forme NFD doublerait un nom NFC), pas de forme
// d'identifiant (un nom ne doit pas masquer l'ID d'un autre dépositaire).
func ValidCustodianName(name string) error {
	n := utf8.RuneCountInString(name)
	if name != strings.TrimSpace(name) || n == 0 || n > 64 {
		return errors.New("chaque dépositaire doit avoir un nom de 1 à 64 caractères, sans espace en bordure")
	}
	for _, r := range name {
		latin := unicode.IsLetter(r) && unicode.Is(unicode.Latin, r) && r < 0x250 // pas d'homoglyphe cyrillique ni pleine chasse
		if !latin && !(r >= '0' && r <= '9') && !strings.ContainsRune(" -_.'", r) {
			return fmt.Errorf("nom de dépositaire %q : caractère %U refusé", name, r)
		}
	}
	if idLike.MatchString(name) {
		return fmt.Errorf("nom de dépositaire %q : forme réservée aux identifiants", name)
	}
	return nil
}

// findCustodian cherche d'abord par identifiant exact, puis par nom.
func findCustodian(q *quorumCfg, name string) (custodian, bool) {
	for _, c := range q.Custodians {
		if name == c.ID {
			return c, true
		}
	}
	for _, c := range q.Custodians {
		if strings.EqualFold(strings.TrimSpace(name), c.Name) {
			return c, true
		}
	}
	return custodian{}, false
}

func openShareKey(rootID string, c custodian, key []byte) (Share, error) {
	y, err := c.Box.open(key, shareAAD(rootID, c.ID, c.X))
	if err != nil {
		return Share{}, errors.New("phrase de passe du dépositaire incorrecte")
	}
	return Share{X: c.X, Y: y}, nil
}

// KeptProof : preuve opaque qu'un dépositaire conservé a saisi sa phrase
// (elle a ouvert sa part en service), avec une clé dérivée de cette même
// phrase sous un sel neuf pour chiffrer sa prochaine part. Les champs ne
// sont pas exportés : seul ce paquet en fabrique.
type KeptProof struct {
	id, rootID string
	key        []byte
	box        box // paramètres et sel neuf, Data vide
}

// Wipe efface la clé de la preuve.
func (p *KeptProof) Wipe() {
	if p != nil {
		secmem.Wipe(p.key)
	}
}

func (s *Software) lookup(name string) (custodian, string, error) {
	s.kmu.RLock()
	q, rootID := s.body.Quorum, s.body.RootID
	s.kmu.RUnlock()
	if q == nil {
		return custodian{}, "", errors.New("aucun quorum n'est configuré")
	}
	c, ok := findCustodian(q, name)
	if !ok {
		return custodian{}, rootID, errUnknownCustodian
	}
	return c, rootID, nil
}

// CustodianID résout un nom ou un identifiant saisi, sans calcul coûteux.
func (s *Software) CustodianID(name string) (string, bool) {
	c, _, err := s.lookup(name)
	return c.ID, err == nil
}

// ChangePassphrase : un dépositaire remplace lui-même sa phrase (au
// terminal). La part ne change pas ; elle est rechiffrée sous la nouvelle
// phrase avec un sel neuf, et marquée « fixée au terminal ».
func (s *Software) ChangePassphrase(name, oldPass, newPass string) (CustodianInfo, error) {
	if utf8.RuneCountInString(newPass) < MinCustodianPass {
		return CustodianInfo{}, fmt.Errorf("la nouvelle phrase doit compter au moins %d caractères", MinCustodianPass)
	}
	if newPass == oldPass {
		return CustodianInfo{}, errors.New("la nouvelle phrase doit différer de l'ancienne")
	}
	sh, ci, err := s.OpenShare(name, oldPass)
	if err != nil {
		return CustodianInfo{}, err
	}
	defer WipeShares([]Share{sh})
	s.kmu.RLock()
	old := s.body
	s.kmu.RUnlock()
	bx, k, err := sealWithPassphrase(newPass, sh.Y, shareAAD(old.RootID, ci.ID, sh.X))
	if err != nil {
		return CustodianInfo{}, err
	}
	secmem.Wipe(k)
	s.kmu.Lock()
	defer s.kmu.Unlock()
	if s.body != old {
		return CustodianInfo{}, errors.New("la configuration du keystore a changé entre-temps : recommencez")
	}
	nb := *old
	q := *old.Quorum
	q.Custodians = append([]custodian{}, old.Quorum.Custodians...)
	for i := range q.Custodians {
		if q.Custodians[i].ID == ci.ID {
			q.Custodians[i].Box, q.Custodians[i].TerminalSet = *bx, true
		}
	}
	nb.Quorum = &q
	if err := (&masterFile{body: &nb}).write(s.dir, s.root); err != nil {
		return CustodianInfo{}, err
	}
	s.body = &nb
	ci.TerminalSet = true
	return ci, nil
}

var errUnknownCustodian = errors.New("dépositaire inconnu ou phrase de passe incorrecte")

// OpenShare déchiffre la part d'un dépositaire. Une phrase fausse est
// détectée ici (étiquette GCM), avant toute reconstitution ; un nom inconnu
// coûte le même temps qu'un nom connu.
func (s *Software) OpenShare(name, pass string) (Share, CustodianInfo, error) {
	c, rootID, err := s.lookup(name)
	if errors.Is(err, errUnknownCustodian) {
		burnArgon(pass)
	}
	if err != nil {
		return Share{}, CustodianInfo{}, err
	}
	k, err := c.Box.derive(pass)
	if err != nil {
		return Share{}, CustodianInfo{}, err
	}
	defer secmem.Wipe(k)
	sh, err := openShareKey(rootID, c, k)
	if err != nil {
		return Share{}, CustodianInfo{}, errUnknownCustodian
	}
	return sh, CustodianInfo{ID: c.ID, Name: c.Name, Added: c.Added, TerminalSet: c.TerminalSet}, nil
}

// OpenShareRekey : OpenShare, plus une preuve pour conserver ce dépositaire
// lors d'une reconfiguration (deux dérivations Argon2id).
func (s *Software) OpenShareRekey(name, pass string) (Share, *KeptProof, CustodianInfo, error) {
	sh, ci, err := s.OpenShare(name, pass)
	if err != nil {
		return Share{}, nil, CustodianInfo{}, err
	}
	p, err := newProof(ci.ID, s.QuorumStatus().rootID, pass)
	if err != nil {
		WipeShares([]Share{sh})
		return Share{}, nil, CustodianInfo{}, err
	}
	return sh, p, ci, nil
}

func newProof(id, rootID, pass string) (*KeptProof, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	bx := box{KDF: kdfArgon2id, Salt: base64.StdEncoding.EncodeToString(salt), T: argonT, M: argonM, P: argonP}
	k, err := bx.derive(pass)
	if err != nil {
		return nil, err
	}
	return &KeptProof{id: id, rootID: rootID, key: k, box: bx}, nil
}

// WipeShares efface les parts en mémoire.
func WipeShares(sh []Share) {
	for _, x := range sh {
		secmem.Wipe(x.Y)
	}
}

// checkQuorum vérifie que les parts, au moins M, reconstituent la clé racine
// en service. À appeler sous s.kmu.
func (s *Software) checkQuorum(approval []Share) error {
	q := s.body.Quorum
	if q == nil {
		return nil // pas encore de quorum : l'administrateur seul décide
	}
	if len(approval) < q.Threshold {
		return fmt.Errorf("quorum non atteint : %d approbation(s) sur %d requises", len(approval), q.Threshold)
	}
	root, err := shamirCombine(approval)
	if err != nil {
		return err
	}
	defer secmem.Wipe(root)
	if subtle.ConstantTimeCompare(root, s.root) != 1 {
		return errors.New("les parts présentées ne reconstituent pas la clé racine")
	}
	return nil
}

// CheckQuorum est la version publique de checkQuorum.
func (s *Software) CheckQuorum(approval []Share) error {
	s.kmu.RLock()
	defer s.kmu.RUnlock()
	return s.checkQuorum(approval)
}

// QuorumRequired indique si les opérations sensibles exigent le quorum.
func (s *Software) QuorumRequired() bool {
	s.kmu.RLock()
	defer s.kmu.RUnlock()
	return s.body.Quorum != nil
}

// TerminalOnly indique si les dépositaires n'approuvent qu'au terminal du
// serveur (rempart approve), jamais dans le navigateur de l'administrateur.
func (s *Software) TerminalOnly() bool {
	s.kmu.RLock()
	defer s.kmu.RUnlock()
	return s.body.Quorum != nil && s.body.Quorum.TerminalOnly
}

// ---- reconfiguration (cérémonie) ----

// NewCustodian : un dépositaire de la nouvelle configuration. Nouveau :
// Name et Passphrase. Conservé : KeepID, et soit Proof (obtenue à son
// approbation), soit Passphrase, vérifiée contre sa part en service — un
// tiers ne peut donc pas lui substituer une phrase de son choix.
type NewCustodian struct {
	Name       string
	Passphrase string
	KeepID     string
	Proof      *KeptProof
}

type Reconfig struct {
	Mode         string
	Threshold    int
	Custodians   []NewCustodian // vide : suppression du quorum (mode auto seulement)
	TerminalOnly bool           // approbations au terminal seulement
	// ServerPassphrase : nécessaire pour passer en mode auto quand le
	// keystore ne connaît pas encore de phrase de passe serveur.
	ServerPassphrase string
}

func (r *Reconfig) validate() error {
	switch r.Mode {
	case ModeAuto, ModeQuorum:
	default:
		return fmt.Errorf("mode %q inconnu", r.Mode)
	}
	n := len(r.Custodians)
	if n == 0 {
		if r.Mode == ModeQuorum {
			return errors.New("le mode quorum exige des dépositaires")
		}
		return nil
	}
	if r.Threshold < 2 || r.Threshold > n || n > MaxCustodians {
		return fmt.Errorf("quorum invalide : il faut 2 ≤ M ≤ N ≤ %d", MaxCustodians)
	}
	names, passes := map[string]bool{}, map[string]bool{}
	for _, c := range r.Custodians {
		if c.KeepID != "" {
			if c.Proof == nil && c.Passphrase == "" {
				return errors.New("un dépositaire conservé doit confirmer sa phrase de passe")
			}
			continue // nom et phrase vérifiés contre la configuration en service
		}
		if err := ValidCustodianName(c.Name); err != nil {
			return err
		}
		if names[strings.ToLower(c.Name)] {
			return fmt.Errorf("dépositaire %q en double", c.Name)
		}
		names[strings.ToLower(c.Name)] = true
		if utf8.RuneCountInString(c.Passphrase) < MinCustodianPass {
			return fmt.Errorf("la phrase de passe de %s doit compter au moins %d caractères", c.Name, MinCustodianPass)
		}
		if passes[c.Passphrase] {
			return errors.New("deux dépositaires ont la même phrase de passe")
		}
		passes[c.Passphrase] = true
	}
	return nil
}

// Reconfigure installe une nouvelle clé racine, la protège selon r, et
// met en service une KEK neuve qui n'a jamais existé sous l'ancienne clé
// racine : un ancien master.json, même accompagné des phrases de dépositaires
// retirés ou de l'ancienne phrase serveur, n'ouvre aucune enveloppe écrite
// ensuite. Limite : le réchiffrement change l'enveloppe, pas les clés de
// données ni les clés de signature ; une copie antérieure d'un fichier,
// avec l'ancien master.json, en livre encore la clé (dont celle du journal
// du jour). Après le retrait d'un dépositaire, renouveler les clés DNSSEC et
// TLS complète la révocation. Les générations antérieures deviennent « remplacées » :
// PurgeSuperseded les détruit dès que plus aucune donnée ne les utilise,
// sous l'autorité de ce quorum. Si un quorum existe, approval doit le satisfaire.
//
// Les dérivations Argon2id (une par dépositaire) se font hors du verrou du
// trousseau, pour ne pas bloquer les chiffrements en cours.
func (s *Software) Reconfigure(r Reconfig, approval []Share) error {
	if err := r.validate(); err != nil {
		return err
	}
	if err := s.CheckQuorum(approval); err != nil {
		return err // échec rapide, avant tout calcul coûteux
	}
	s.kmu.RLock()
	old := s.body
	var oldPK []byte
	if s.pk != nil {
		oldPK = append([]byte(nil), s.pk...)
		secmem.Lock(oldPK)
	}
	s.kmu.RUnlock()
	defer secmem.Wipe(oldPK)

	nb := *old
	nb.Mode, nb.RootID, nb.Created = r.Mode, randomID(), now()
	root, err := randomKey()
	if err != nil {
		return err
	}
	var pk []byte
	ok := false
	defer func() {
		if !ok {
			secmem.Wipe(root)
			secmem.Wipe(pk)
		}
	}()

	// Phrase de passe serveur.
	nb.Passphrase = nil
	if r.Mode == ModeAuto {
		switch {
		case r.ServerPassphrase != "":
			bx, k, err := sealWithPassphrase(r.ServerPassphrase, root, rootAAD(nb.RootID, "passphrase"))
			if err != nil {
				return err
			}
			nb.Passphrase, pk = bx, k
		case oldPK != nil:
			bx := *old.Passphrase
			if err := bx.seal(oldPK, root, rootAAD(nb.RootID, "passphrase")); err != nil {
				return err
			}
			pk = append([]byte(nil), oldPK...)
			secmem.Lock(pk)
			nb.Passphrase = &bx
		case len(r.Custodians) == 0 && old.Passphrase != nil && old.Passphrase.KDF == kdfNone:
			nb.Passphrase = &box{KDF: kdfNone, Data: base64.StdEncoding.EncodeToString(root)}
		default:
			return errors.New("le mode auto exige une phrase de passe serveur : définissez REMPART_KEYSTORE_PASSPHRASE_FILE et redémarrez, ou restez en mode quorum")
		}
	}

	// Parts des dépositaires.
	nb.Quorum = nil
	if len(r.Custodians) > 0 {
		shares, err := shamirSplit(root, len(r.Custodians), r.Threshold)
		if err != nil {
			return err
		}
		defer WipeShares(shares)
		q := &quorumCfg{Threshold: r.Threshold, Since: now(), TerminalOnly: r.TerminalOnly}
		seen := map[string]bool{}
		for i, c := range r.Custodians {
			if c.KeepID == "" {
				cu := custodian{ID: randomID()[:8], Name: c.Name, X: shares[i].X, Added: now()}
				bx, k, err := sealWithPassphrase(c.Passphrase, shares[i].Y, shareAAD(nb.RootID, cu.ID, cu.X))
				if err != nil {
					return err
				}
				secmem.Wipe(k)
				cu.Box = *bx
				q.Custodians = append(q.Custodians, cu)
				continue
			}
			var prev custodian
			found := false
			if old.Quorum != nil {
				for _, oc := range old.Quorum.Custodians {
					if oc.ID == c.KeepID {
						prev, found = oc, true
					}
				}
			}
			if !found || seen[c.KeepID] {
				return fmt.Errorf("dépositaire %q inconnu ou en double", c.KeepID)
			}
			seen[c.KeepID] = true
			proof := c.Proof
			if proof == nil {
				k, err := prev.Box.derive(c.Passphrase)
				if err != nil {
					return err
				}
				cur, err := openShareKey(old.RootID, prev, k)
				secmem.Wipe(k)
				if err != nil {
					return fmt.Errorf("phrase de passe de %s incorrecte", prev.Name)
				}
				secmem.Wipe(cur.Y)
				if proof, err = newProof(prev.ID, old.RootID, c.Passphrase); err != nil {
					return err
				}
				defer proof.Wipe()
			}
			if proof.id != prev.ID || proof.rootID != old.RootID {
				return fmt.Errorf("preuve de %s invalide ou périmée", prev.Name)
			}
			// Phrase inchangée : l'indicateur « fixée au terminal » ne survit que
			// si la preuve vient d'une approbation (phrase non ressaisie ici).
			cu := custodian{ID: prev.ID, Name: prev.Name, X: shares[i].X, Added: prev.Added, TerminalSet: prev.TerminalSet && c.Proof != nil}
			bx := proof.box
			if err := bx.seal(proof.key, shares[i].Y, shareAAD(nb.RootID, cu.ID, cu.X)); err != nil {
				return err
			}
			cu.Box = bx
			q.Custodians = append(q.Custodians, cu)
		}
		for i, a := range q.Custodians {
			for _, b := range q.Custodians[i+1:] {
				if strings.EqualFold(a.Name, b.Name) {
					return fmt.Errorf("dépositaire %q en double", a.Name)
				}
			}
		}
		nb.Quorum = q
	}

	// Bascule sous verrou : la configuration ne doit pas avoir changé entre-temps.
	s.kmu.Lock()
	defer s.kmu.Unlock()
	if s.body != old {
		return errors.New("la configuration du keystore a changé pendant la cérémonie : recommencez")
	}
	if err := s.checkQuorum(approval); err != nil {
		return err
	}
	nb.Keyring = append([]kekEntry{}, old.Keyring...)
	if err := rewrapKeyring(s.root, root, old.RootID, &nb); err != nil {
		return err
	}
	keks := make(map[uint32]cipher.AEAD, len(s.keks)+1)
	for g, a := range s.keks {
		keks[g] = a
	}
	if err := addGeneration(root, &nb, keks); err != nil {
		return err
	}
	mf := &masterFile{body: &nb}
	if err := mf.write(s.dir, root); err != nil {
		return err
	}
	ok = true
	secmem.Wipe(s.root)
	secmem.Wipe(s.pk)
	s.body, s.root, s.pk, s.keks = &nb, root, pk, keks
	s.superseded = map[uint32]bool{}
	for _, e := range old.Keyring {
		s.superseded[e.Gen] = true
	}
	return nil
}

// PurgeSuperseded détruit les générations remplacées par la dernière
// reconfiguration qui ne chiffrent plus aucune donnée (inUse : générations
// trouvées par l'inventaire après réchiffrement). L'autorisation vient du
// quorum qui a approuvé la reconfiguration ; elle ne survit pas à un
// redémarrage. Renvoie les générations détruites et celles qui restent.
func (s *Software) PurgeSuperseded(inUse map[uint32]bool) (destroyed, left []uint32, err error) {
	s.kmu.Lock()
	defer s.kmu.Unlock()
	if len(s.superseded) == 0 {
		return nil, nil, nil
	}
	nb := *s.body
	nb.Keyring = nil
	keks := make(map[uint32]cipher.AEAD, len(s.keks))
	for _, e := range s.body.Keyring {
		if s.superseded[e.Gen] && e.Gen != nb.Current {
			if inUse[e.Gen] {
				left = append(left, e.Gen)
			} else {
				destroyed = append(destroyed, e.Gen)
				continue
			}
		}
		nb.Keyring = append(nb.Keyring, e)
		keks[e.Gen] = s.keks[e.Gen]
	}
	if len(destroyed) == 0 {
		return nil, left, nil
	}
	if err := (&masterFile{body: &nb}).write(s.dir, s.root); err != nil {
		return nil, left, err
	}
	s.body, s.keks = &nb, keks
	for _, g := range destroyed {
		delete(s.superseded, g)
	}
	return destroyed, left, nil
}

// rewrapKeyring rechiffre chaque KEK de b (encore sous oldRoot/oldID) sous newRoot/b.RootID.
func rewrapKeyring(oldRoot, newRoot []byte, oldID string, b *masterBody) error {
	ok, nk := rootSubkey(oldRoot, "enc"), rootSubkey(newRoot, "enc")
	defer secmem.Wipe(ok)
	defer secmem.Wipe(nk)
	for i, e := range b.Keyring {
		ct, err := base64.StdEncoding.DecodeString(e.Data)
		if err != nil {
			return err
		}
		kek, err := aeadOpen(ok, ct, kekAAD(oldID, e.Gen))
		if err != nil {
			return fmt.Errorf("KEK génération %d : %w", e.Gen, err)
		}
		nct, err := aeadSeal(nk, kek, kekAAD(b.RootID, e.Gen))
		secmem.Wipe(kek)
		if err != nil {
			return err
		}
		b.Keyring[i].Data = base64.StdEncoding.EncodeToString(nct)
	}
	return nil
}

func addGeneration(root []byte, b *masterBody, keks map[uint32]cipher.AEAD) error {
	var gen uint32
	for _, e := range b.Keyring {
		gen = max(gen, e.Gen)
	}
	gen++
	kek, err := randomKey()
	if err != nil {
		return err
	}
	defer secmem.Wipe(kek)
	e, err := sealKEK(root, b.RootID, gen, kek)
	if err != nil {
		return err
	}
	a, err := gcm(kek)
	if err != nil {
		return err
	}
	b.Keyring = append(b.Keyring, e)
	b.Current = gen
	keks[gen] = a
	return nil
}

// ---- rotation de la KEK ----

// RotateKEK crée une KEK neuve qui chiffre désormais toutes les nouvelles
// données. Les anciennes générations restent lisibles jusqu'au
// réchiffrement des données puis à leur destruction. Pas de quorum : une
// rotation ne réduit jamais la sécurité.
func (s *Software) RotateKEK() (uint32, error) {
	s.kmu.Lock()
	defer s.kmu.Unlock()
	nb := *s.body
	nb.Keyring = append([]kekEntry{}, s.body.Keyring...)
	keks := make(map[uint32]cipher.AEAD, len(s.keks)+1)
	for g, a := range s.keks {
		keks[g] = a
	}
	if err := addGeneration(s.root, &nb, keks); err != nil {
		return 0, err
	}
	if err := (&masterFile{body: &nb}).write(s.dir, s.root); err != nil {
		return 0, err
	}
	s.body, s.keks = &nb, keks
	return nb.Current, nil
}

// RotationDue indique si la KEK courante a dépassé sa durée de vie.
func (s *Software) RotationDue(t time.Time) bool {
	s.kmu.RLock()
	defer s.kmu.RUnlock()
	if s.body.RotateDays <= 0 {
		return false
	}
	for _, e := range s.body.Keyring {
		if e.Gen == s.body.Current {
			return !t.Before(e.Created.AddDate(0, 0, s.body.RotateDays))
		}
	}
	return false
}

// RewrapKeys rechiffre les clés de signature par la KEK courante.
func (s *Software) RewrapKeys() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, _ := filepath.Glob(filepath.Join(s.dir, "keys", "*.key"))
	n := 0
	for _, path := range files {
		label := strings.TrimSuffix(filepath.Base(path), ".key")
		ct, err := os.ReadFile(path)
		if err != nil {
			return n, err
		}
		if s.IsCurrent(ct) {
			continue
		}
		aad := []byte("rempart-key:" + label)
		der, err := s.Unwrap(ct, aad)
		if err != nil {
			return n, fmt.Errorf("clé %s : %w", label, err)
		}
		nct, err := s.Wrap(der, aad)
		secmem.Wipe(der)
		if err != nil {
			return n, err
		}
		if err := writeAtomic(path, nct); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// RetireGenerations marque comme retirées les générations que plus aucune
// donnée n'utilise (inUse : générations rencontrées lors du contrôle).
func (s *Software) RetireGenerations(inUse map[uint32]bool) ([]uint32, error) {
	s.kmu.Lock()
	defer s.kmu.Unlock()
	nb := *s.body
	nb.Keyring = append([]kekEntry{}, s.body.Keyring...)
	var done []uint32
	t := now()
	for i, e := range nb.Keyring {
		if e.Gen != nb.Current && e.Retired == nil && !inUse[e.Gen] {
			nb.Keyring[i].Retired = &t
			done = append(done, e.Gen)
		}
	}
	if len(done) == 0 {
		return nil, nil
	}
	if err := (&masterFile{body: &nb}).write(s.dir, s.root); err != nil {
		return nil, err
	}
	s.body = &nb
	return done, nil
}

// DestroyGeneration efface définitivement une KEK retirée : les sauvegardes
// chiffrées par elle deviennent illisibles (effacement cryptographique).
// Exige le quorum quand il est configuré.
func (s *Software) DestroyGeneration(gen uint32, approval []Share) error {
	s.kmu.Lock()
	defer s.kmu.Unlock()
	if err := s.checkQuorum(approval); err != nil {
		return err
	}
	if gen == s.body.Current {
		return errors.New("la génération courante ne peut pas être détruite")
	}
	nb := *s.body
	nb.Keyring = nil
	found := false
	for _, e := range s.body.Keyring {
		if e.Gen == gen {
			if e.Retired == nil {
				return fmt.Errorf("la génération %d sert encore : réchiffrez les données d'abord", gen)
			}
			found = true
			continue
		}
		nb.Keyring = append(nb.Keyring, e)
	}
	if !found {
		return fmt.Errorf("génération %d inconnue", gen)
	}
	if err := (&masterFile{body: &nb}).write(s.dir, s.root); err != nil {
		return err
	}
	keks := make(map[uint32]cipher.AEAD, len(s.keks))
	for g, a := range s.keks {
		if g != gen {
			keks[g] = a
		}
	}
	s.body, s.keks = &nb, keks
	return nil
}

// SetRotation change la période de rotation planifiée (0 : désactivée).
func (s *Software) SetRotation(days int, approval []Share) error {
	if days < 0 || days > 3650 {
		return errors.New("période de rotation invalide (0 à 3650 jours)")
	}
	s.kmu.Lock()
	defer s.kmu.Unlock()
	if err := s.checkQuorum(approval); err != nil {
		return err
	}
	nb := *s.body
	nb.RotateDays = days
	if err := (&masterFile{body: &nb}).write(s.dir, s.root); err != nil {
		return err
	}
	s.body = &nb
	return nil
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

// ---- déverrouillage au démarrage ----

// Unsealer rassemble les parts des dépositaires quand le keystore démarre
// verrouillé. Les parts restent en mémoire verrouillée au plus UnsealTTL
// après la première, puis sont effacées (minuterie, sans attendre d'appel).
type Unsealer struct {
	dir    string
	mf     *masterFile
	mu     sync.Mutex
	shares map[string]Share
	first  time.Time
}

const UnsealTTL = 15 * time.Minute

func NewUnsealer(dir string) (*Unsealer, error) {
	raw, err := os.ReadFile(masterPath(dir))
	if err != nil {
		return nil, err
	}
	mf, err := parseMaster(raw)
	if err != nil {
		return nil, err
	}
	if mf.body.Quorum == nil {
		return nil, errors.New("aucun quorum n'est configuré dans ce keystore")
	}
	return &Unsealer{dir: dir, mf: mf, shares: map[string]Share{}}, nil
}

func (u *Unsealer) Need() int { return u.mf.body.Quorum.Threshold }

// Progress renvoie les dépositaires déjà présentés et le seuil.
func (u *Unsealer) Progress() (names []string, need int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.expire()
	for id := range u.shares {
		for _, c := range u.mf.body.Quorum.Custodians {
			if c.ID == id {
				names = append(names, c.Name)
			}
		}
	}
	sort.Strings(names)
	return names, u.Need()
}

func (u *Unsealer) expire() {
	if len(u.shares) > 0 && time.Since(u.first) > UnsealTTL {
		u.Reset()
	}
}

// Reset efface les parts reçues.
func (u *Unsealer) Reset() {
	for id, sh := range u.shares {
		secmem.Wipe(sh.Y)
		delete(u.shares, id)
	}
}

// Add vérifie la phrase d'un dépositaire et garde sa part. Quand le seuil
// est atteint, il renvoie le keystore ouvert (et efface les parts).
func (u *Unsealer) Add(name, pass string) (have int, ks *Software, err error) {
	q := u.mf.body.Quorum
	c, found := findCustodian(q, name)
	var sh Share
	if found {
		var k []byte
		if k, err = c.Box.derive(pass); err == nil {
			sh, err = openShareKey(u.mf.body.RootID, c, k)
			secmem.Wipe(k)
		}
	} else {
		burnArgon(pass)
		err = errors.New("dépositaire inconnu")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.expire()
	if err != nil {
		return len(u.shares), nil, errors.New("dépositaire inconnu ou phrase de passe incorrecte")
	}
	if old, dup := u.shares[c.ID]; dup {
		secmem.Wipe(old.Y)
	}
	if len(u.shares) == 0 {
		u.first = time.Now()
		// Effacement actif à l'échéance, même si plus personne ne se présente.
		first := u.first
		time.AfterFunc(UnsealTTL, func() {
			u.mu.Lock()
			if u.first.Equal(first) {
				u.Reset()
			}
			u.mu.Unlock()
		})
	}
	u.shares[c.ID] = sh
	if len(u.shares) < q.Threshold {
		return len(u.shares), nil, nil
	}
	list := make([]Share, 0, len(u.shares))
	for _, s := range u.shares {
		list = append(list, s)
	}
	root, err := shamirCombine(list)
	u.Reset()
	if err != nil {
		return 0, nil, err
	}
	secmem.Lock(root)
	ks, err = newSoftware(u.dir, u.mf, root, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("déverrouillage refusé : %w", err)
	}
	return q.Threshold, ks, nil
}
