// quorum.go - API du quorum M-sur-N et de la rotation des clés du keystore logiciel.
// Entrées : demandes de l'interface (session seulement, jamais par jeton) ; sorties : JSON, audit.
// Rempart ; les phrases de passe des dépositaires ne sont ni journalisées ni conservées.

package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/migrate"
	"github.com/rempart-dns/rempart/internal/state"
)

const quorumOpTTL = 10 * time.Minute

// quorumOp : une opération sensible en attente d'approbations. Les parts
// déchiffrées restent en mémoire verrouillée jusqu'à l'exécution, l'annulation
// ou l'expiration (minuterie), puis sont effacées.
type quorumOp struct {
	ID      string      `json:"id"`
	Kind    string      `json:"kind"` // reconfigure | destroy | policy
	Gen     uint32      `json:"gen,omitempty"`
	Days    int         `json:"days,omitempty"`
	Plan    *reconfPlan `json:"plan,omitempty"`
	By      string      `json:"by"`
	Created time.Time   `json:"created"`
	shares  map[string]keystore.Share
	proofs  map[string]*keystore.KeptProof // approbateurs, pour leur rechiffrer une part
	names   map[string]string
}

// reconfPlan : ce que les dépositaires approuvent pour une reconfiguration.
// L'exécution doit correspondre exactement : l'administrateur ne peut pas
// changer de liste, de seuil ou de mode après les approbations.
type reconfPlan struct {
	Mode         string   `json:"mode"`
	Threshold    int      `json:"threshold"`
	Keep         []string `json:"keep"` // identifiants des dépositaires conservés
	Add          []string `json:"add"`  // noms des nouveaux dépositaires
	TerminalOnly bool     `json:"terminal_only"`
}

func (p *reconfPlan) normalize() {
	sort.Strings(p.Keep)
	sort.Slice(p.Add, func(i, j int) bool { return strings.ToLower(p.Add[i]) < strings.ToLower(p.Add[j]) })
}

func (p *reconfPlan) validate() error {
	for _, n := range p.Add {
		if err := keystore.ValidCustodianName(n); err != nil {
			return err
		}
	}
	return nil
}

// equal compare élément par élément (jamais par concaténation : un
// séparateur glissé dans un nom ferait passer deux noms pour un).
func (p reconfPlan) equal(o reconfPlan) bool {
	p.Keep, p.Add = append([]string(nil), p.Keep...), append([]string(nil), p.Add...)
	o.Keep, o.Add = append([]string(nil), o.Keep...), append([]string(nil), o.Add...)
	p.normalize()
	o.normalize()
	if p.Mode != o.Mode || p.Threshold != o.Threshold || p.TerminalOnly != o.TerminalOnly || len(p.Keep) != len(o.Keep) || len(p.Add) != len(o.Add) {
		return false
	}
	for i := range p.Keep {
		if p.Keep[i] != o.Keep[i] {
			return false
		}
	}
	for i := range p.Add {
		if !strings.EqualFold(p.Add[i], o.Add[i]) {
			return false
		}
	}
	return true
}

// nameGuard limite les essais par dépositaire visé : la réussite d'un autre
// dépositaire ne remet pas le compteur à zéro.
type nameGuard struct {
	mu   sync.Mutex
	fail map[string]*attempts
}

func (g *nameGuard) key(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

func (g *nameGuard) blocked(name string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	if a, ok := g.fail[g.key(name)]; ok && time.Now().Before(a.until) {
		return time.Until(a.until)
	}
	return 0
}

func (g *nameGuard) failed(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fail == nil {
		g.fail = map[string]*attempts{}
	}
	a, ok := g.fail[g.key(name)]
	if !ok {
		a = &attempts{}
		g.fail[g.key(name)] = a
	}
	a.n++
	if a.n >= 5 {
		a.until = time.Now().Add(time.Duration(1<<min(a.n-5, 10)) * time.Minute)
	}
}

func (g *nameGuard) success(name string) {
	g.mu.Lock()
	delete(g.fail, g.key(name))
	g.mu.Unlock()
}

type quorumState struct {
	mu    sync.Mutex
	op    *quorumOp
	guard nameGuard
	rot   sync.Mutex // une rotation ou un réchiffrement à la fois
}

func (op *quorumOp) wipe() {
	for _, s := range op.shares {
		keystore.WipeShares([]keystore.Share{s})
	}
	for _, p := range op.proofs {
		p.Wipe()
	}
}

func (q *quorumState) clear() {
	if q.op != nil {
		q.op.wipe()
		q.op = nil
	}
}

// current renvoie l'opération en cours (nil si expirée, alors effacée).
func (q *quorumState) current() *quorumOp {
	if q.op != nil && time.Since(q.op.Created) > quorumOpTTL {
		q.clear()
	}
	return q.op
}

func (a *API) software(w http.ResponseWriter) (*keystore.Software, bool) {
	sw, ok := a.KS.(*keystore.Software)
	if !ok {
		jsonError(w, http.StatusConflict, "le keystore en service est un HSM : son quorum se règle sur le HSM (M sur N du constructeur)")
	}
	return sw, ok
}

func (a *API) quorumStatus(w http.ResponseWriter, _ *http.Request, _ string) {
	sw, ok := a.KS.(*keystore.Software)
	if !ok {
		writeJSON(w, map[string]any{"backend": a.KS.Backend()})
		return
	}
	inv, err := migrate.Inventory(a.DataDir, sw.Dir())
	usage := map[uint32]int{}
	for g, files := range inv {
		usage[g] = len(files)
	}
	out := map[string]any{"backend": "software", "status": sw.QuorumStatus(), "usage": usage, "server_passphrase_available": a.serverPassAvailable()}
	if err != nil {
		out["inventory_error"] = err.Error()
	}
	if op := a.opSummary(); op != nil {
		out["op"] = op
	}
	writeJSON(w, out)
}

// opSummary décrit l'opération en attente (nil s'il n'y en a pas).
func (a *API) opSummary() map[string]any {
	a.quorum.mu.Lock()
	defer a.quorum.mu.Unlock()
	op := a.quorum.current()
	if op == nil {
		return nil
	}
	names := make([]string, 0, len(op.names))
	for _, n := range op.names {
		names = append(names, n)
	}
	sort.Strings(names)
	return map[string]any{"id": op.ID, "kind": op.Kind, "gen": op.Gen, "days": op.Days, "by": op.By, "plan": op.Plan,
		"approved_by": names, "expires": op.Created.Add(quorumOpTTL)}
}

func (a *API) serverPassAvailable() bool {
	if a.ServerPassphrase == nil {
		return false
	}
	p, err := a.ServerPassphrase()
	return err == nil && p != ""
}

// quorumOpen ouvre une demande d'opération sensible.
func (a *API) quorumOpen(w http.ResponseWriter, r *http.Request, user string) {
	sw, ok := a.software(w)
	if !ok {
		return
	}
	var in struct {
		Kind string
		Gen  uint32
		Days int
		Plan *reconfPlan
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Kind != "reconfigure" && in.Kind != "destroy" && in.Kind != "policy" {
		jsonError(w, http.StatusBadRequest, "opération inconnue")
		return
	}
	if in.Kind == "reconfigure" {
		if in.Plan == nil {
			jsonError(w, http.StatusBadRequest, "une reconfiguration doit décrire la nouvelle configuration")
			return
		}
		in.Plan.normalize()
		if err := in.Plan.validate(); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := limitNewcomers(len(in.Plan.Add), in.Plan.Threshold); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		in.Plan = nil
	}
	if !sw.QuorumRequired() {
		jsonError(w, http.StatusBadRequest, "aucun quorum n'est configuré : l'opération s'exécute directement")
		return
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	a.quorum.mu.Lock()
	a.quorum.clear()
	op := &quorumOp{ID: hex.EncodeToString(b), Kind: in.Kind, Gen: in.Gen, Days: in.Days, Plan: in.Plan, By: user, Created: time.Now(),
		shares: map[string]keystore.Share{}, proofs: map[string]*keystore.KeptProof{}, names: map[string]string{}}
	a.quorum.op = op
	a.quorum.mu.Unlock()
	// Effacement actif à l'échéance, même si personne ne revient sur la page.
	time.AfterFunc(quorumOpTTL, func() {
		a.quorum.mu.Lock()
		if a.quorum.op == op {
			a.quorum.clear()
		}
		a.quorum.mu.Unlock()
	})
	a.record(user, "quorum.demande", op.describe(sw))
	writeJSON(w, map[string]bool{"ok": true})
}

// limitNewcomers : les phrases des nouveaux dépositaires sont saisies dans la
// session de l'administrateur ; il ne doit jamais en connaître M. Chaque
// quorum possible garde donc au moins un dépositaire déjà enrôlé.
func limitNewcomers(add, threshold int) error {
	if add > 0 && add >= threshold {
		return fmt.Errorf("au plus %d nouveau(x) dépositaire(s) par reconfiguration avec un seuil de %d : remplacez l'équipe en plusieurs fois", threshold-1, threshold)
	}
	return nil
}

func describeOp(kind string, gen uint32, days int) string {
	switch kind {
	case "destroy":
		return fmt.Sprintf("destruction de la KEK génération %d", gen)
	case "policy":
		return fmt.Sprintf("rotation tous les %d jours", days)
	}
	return "reconfiguration du quorum (nouvelle clé racine, nouvelle KEK)"
}

// describe : texte de l'opération pour l'audit et le terminal, plan compris.
func (op *quorumOp) describe(sw *keystore.Software) string {
	d := describeOp(op.Kind, op.Gen, op.Days)
	if p := op.Plan; p != nil {
		names := map[string]string{}
		for _, c := range sw.QuorumStatus().Custodians {
			names[c.ID] = c.Name
		}
		var keep []string
		for _, id := range p.Keep {
			keep = append(keep, names[id])
		}
		via := "interface"
		if p.TerminalOnly {
			via = "terminal seulement"
		}
		d += fmt.Sprintf(" : mode %s, seuil %d sur %d, conservés [%s], nouveaux [%s], approbations %s", p.Mode, p.Threshold, len(p.Keep)+len(p.Add),
			strings.Join(keep, ", "), strings.Join(p.Add, ", "), via)
	}
	return d
}

// approve vérifie la phrase d'un dépositaire pour l'opération en cours et
// garde sa part. channel : "interface" ou "terminal".
func (a *API) approve(sw *keystore.Software, opID, name, pass, channel string) (int, int, error) {
	gk := a.guardKey(sw, channel, name)
	if d := a.quorum.guard.blocked(gk); d > 0 {
		return 0, 0, fmt.Errorf("trop d'échecs pour ce dépositaire, réessayez dans %s", d.Round(time.Second))
	}
	// En mode « terminal seulement », seule une phrase fixée au terminal compte :
	// une phrase passée par la session de l'administrateur peut lui être connue.
	if sw.TerminalOnly() {
		id, _ := sw.CustodianID(name)
		for _, c := range sw.QuorumStatus().Custodians {
			if c.ID == id && !c.TerminalSet {
				return 0, 0, fmt.Errorf("%s doit d'abord fixer sa phrase au terminal : podman exec -it rempart rempart passwd", c.Name)
			}
		}
	}
	a.quorum.mu.Lock()
	op := a.quorum.current()
	a.quorum.mu.Unlock()
	if op == nil || (opID != "" && op.ID != opID) {
		return 0, 0, errors.New("aucune opération en attente, ou elle a expiré")
	}
	var (
		sh    keystore.Share
		proof *keystore.KeptProof
		c     keystore.CustodianInfo
		err   error
	)
	if op.Kind == "reconfigure" {
		sh, proof, c, err = sw.OpenShareRekey(name, pass)
	} else {
		sh, c, err = sw.OpenShare(name, pass)
	}
	if err != nil {
		a.quorum.guard.failed(gk)
		// Le nom saisi n'est pas journalisé : une phrase tapée par erreur
		// dans ce champ finirait dans l'audit.
		a.record("quorum", "quorum.approbation-échec", channel+" : "+describeOp(op.Kind, op.Gen, op.Days))
		return 0, 0, err
	}
	a.quorum.mu.Lock()
	defer a.quorum.mu.Unlock()
	if a.quorum.current() != op {
		keystore.WipeShares([]keystore.Share{sh})
		proof.Wipe()
		return 0, 0, errors.New("l'opération a changé pendant la vérification")
	}
	if old, dup := op.shares[c.ID]; dup {
		keystore.WipeShares([]keystore.Share{old})
		op.proofs[c.ID].Wipe()
	}
	op.shares[c.ID], op.names[c.ID] = sh, c.Name
	if proof != nil {
		op.proofs[c.ID] = proof
	}
	a.quorum.guard.success(gk)
	a.record(c.Name, "quorum.approbation", channel+" : "+op.describe(sw))
	return len(op.shares), sw.QuorumStatus().Threshold, nil
}

// guardKey : compteur d'échecs par canal et par dépositaire résolu (nom ou
// identifiant donnent le même compteur). Par canal : la session web ne peut
// pas bloquer les approbations faites au terminal.
func (a *API) guardKey(sw *keystore.Software, channel, name string) string {
	if id, ok := sw.CustodianID(name); ok {
		return channel + "|" + id
	}
	return channel + "|?" + strings.ToLower(strings.TrimSpace(name))
}

// quorumApprove : approbation saisie dans l'interface, refusée quand le
// quorum exige le terminal.
func (a *API) quorumApprove(w http.ResponseWriter, r *http.Request, _ string) {
	sw, ok := a.software(w)
	if !ok {
		return
	}
	var in struct{ ID, Name, Passphrase string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if sw.TerminalOnly() {
		jsonError(w, http.StatusForbidden, "ce quorum n'accepte les approbations qu'au terminal du serveur : podman exec -it rempart rempart approve")
		return
	}
	got, need, err := a.approve(sw, in.ID, in.Name, in.Passphrase, "interface")
	if err != nil {
		jsonError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, map[string]any{"approved": got, "need": need})
}

// TerminalApprove : approbation reçue par le socket local (rempart approve).
// Sans nom, renvoie seulement l'opération en attente. Avec un nom, opID doit
// être celui de l'opération que le dépositaire a lue : si l'administrateur
// la remplace pendant la saisie, l'approbation est refusée.
func (a *API) TerminalApprove(opID, name, pass string) (map[string]any, error) {
	sw, ok := a.KS.(*keystore.Software)
	if !ok {
		return nil, errors.New("keystore HSM : pas de quorum logiciel")
	}
	op := a.opSummary()
	if op == nil {
		return nil, errors.New("aucune opération en attente d'approbation")
	}
	a.quorum.mu.Lock()
	cur := a.quorum.current()
	desc := ""
	if cur != nil {
		desc = cur.describe(sw)
	}
	a.quorum.mu.Unlock()
	if cur == nil {
		return nil, errors.New("aucune opération en attente d'approbation")
	}
	op["description"], op["need"] = desc, sw.QuorumStatus().Threshold
	if name == "" {
		return op, nil
	}
	if opID == "" || opID != op["id"].(string) {
		return op, errors.New("l'opération a changé depuis son affichage : relancez rempart approve et relisez-la")
	}
	got, need, err := a.approve(sw, opID, name, pass, "terminal")
	if err != nil {
		return op, err
	}
	op["approved"], op["need"] = got, need
	return op, nil
}

// TerminalPasswd : un dépositaire change lui-même sa phrase au terminal.
func (a *API) TerminalPasswd(name, oldPass, newPass string) error {
	sw, ok := a.KS.(*keystore.Software)
	if !ok {
		return errors.New("keystore HSM : pas de quorum logiciel")
	}
	gk := a.guardKey(sw, "passwd", name)
	if d := a.quorum.guard.blocked(gk); d > 0 {
		return fmt.Errorf("trop d'échecs pour ce dépositaire, réessayez dans %s", d.Round(time.Second))
	}
	ci, err := sw.ChangePassphrase(name, oldPass, newPass)
	if err != nil {
		a.quorum.guard.failed(gk)
		a.record("quorum", "quorum.phrase-échec", "terminal")
		return err
	}
	a.quorum.guard.success(gk)
	a.record(ci.Name, "quorum.phrase-changée", "au terminal")
	return nil
}

func (a *API) quorumCancel(w http.ResponseWriter, _ *http.Request, user string) {
	a.quorum.mu.Lock()
	had := a.quorum.current() != nil
	a.quorum.clear()
	a.quorum.mu.Unlock()
	if had {
		a.record(user, "quorum.annulée", "")
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// takeApproval retire l'opération approuvée du type attendu, avec ses parts
// et, pour une reconfiguration, les preuves des approbateurs. L'appelant les
// efface après usage. Sans quorum configuré, renvoie nil. Tant que le seuil
// n'est pas atteint, l'opération reste en attente.
func (a *API) takeApproval(sw *keystore.Software, id, kind string, check func(*quorumOp) bool) ([]keystore.Share, map[string]*keystore.KeptProof, error) {
	if !sw.QuorumRequired() {
		return nil, nil, nil
	}
	a.quorum.mu.Lock()
	defer a.quorum.mu.Unlock()
	op := a.quorum.current()
	if op == nil || op.ID != id || op.Kind != kind || (check != nil && !check(op)) {
		return nil, nil, errors.New("cette opération exige l'approbation du quorum, pour exactement ces paramètres : ouvrez une demande et faites-la approuver")
	}
	if need := sw.QuorumStatus().Threshold; len(op.shares) < need {
		return nil, nil, fmt.Errorf("quorum non atteint : %d approbation(s) sur %d", len(op.shares), need)
	}
	out := make([]keystore.Share, 0, len(op.shares))
	for _, s := range op.shares {
		out = append(out, s)
	}
	proofs := op.proofs
	a.quorum.op = nil // parts et preuves sont désormais à la charge de l'appelant
	return out, proofs, nil
}

// quorumReconfigure : cérémonie. Première configuration (administrateur
// seul, tous les dépositaires sont nouveaux) ou exécution d'un plan
// approuvé par le quorum : les dépositaires conservés gardent leur phrase
// (preuve obtenue à leur approbation ou, hors mode « terminal seulement »,
// phrase ressaisie et vérifiée contre leur part) ; seuls les nouveaux en
// choisissent une. Toute reconfiguration met en service une KEK neuve,
// rechiffre les données et détruit les générations remplacées.
func (a *API) quorumReconfigure(w http.ResponseWriter, r *http.Request, user string) {
	sw, ok := a.software(w)
	if !ok {
		return
	}
	type cred struct{ ID, Name, Passphrase string }
	var in struct {
		OpID         string `json:"op_id"`
		Password     string
		Mode         string
		Threshold    int
		TerminalOnly bool `json:"terminal_only"`
		Keep         []cred
		Add          []cred
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !CheckPassword(in.Password, a.Store.Get().Admin.PasswordHash) {
		jsonError(w, http.StatusForbidden, "mot de passe administrateur incorrect")
		return
	}
	plan := reconfPlan{Mode: in.Mode, Threshold: in.Threshold, TerminalOnly: in.TerminalOnly}
	for _, c := range in.Keep {
		plan.Keep = append(plan.Keep, c.ID)
	}
	for _, c := range in.Add {
		plan.Add = append(plan.Add, c.Name)
	}
	if err := plan.validate(); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	quorum := sw.QuorumRequired()
	if !quorum && len(in.Keep) > 0 {
		jsonError(w, http.StatusBadRequest, "aucun dépositaire existant à conserver")
		return
	}
	if quorum {
		// Revérifié à l'exécution, pas seulement à l'ouverture de la demande.
		if err := limitNewcomers(len(in.Add), in.Threshold); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	terminalOnly := sw.TerminalOnly()
	approval, proofs, err := a.takeApproval(sw, in.OpID, "reconfigure", func(op *quorumOp) bool { return op.Plan != nil && op.Plan.equal(plan) })
	if err != nil {
		jsonError(w, http.StatusForbidden, err.Error())
		return
	}
	defer keystore.WipeShares(approval)
	defer func() {
		for _, p := range proofs {
			p.Wipe()
		}
	}()
	rc := keystore.Reconfig{Mode: in.Mode, Threshold: in.Threshold, TerminalOnly: in.TerminalOnly}
	for _, c := range in.Keep {
		nc := keystore.NewCustodian{KeepID: c.ID, Proof: proofs[c.ID]}
		if nc.Proof == nil {
			if terminalOnly {
				jsonError(w, http.StatusForbidden, "en mode « terminal seulement », chaque dépositaire conservé doit avoir approuvé au terminal")
				return
			}
			nc.Passphrase = c.Passphrase
		}
		rc.Custodians = append(rc.Custodians, nc)
	}
	for _, c := range in.Add {
		rc.Custodians = append(rc.Custodians, keystore.NewCustodian{Name: c.Name, Passphrase: c.Passphrase})
	}
	// Passer en mode auto exige la phrase serveur que Rempart lira au
	// prochain démarrage, pas une phrase saisie ici : sinon il ne redémarrerait pas.
	if in.Mode == keystore.ModeAuto && a.ServerPassphrase != nil {
		if p, err := a.ServerPassphrase(); err == nil {
			rc.ServerPassphrase = p
		}
	}
	if err := sw.Reconfigure(rc, approval); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	st := sw.QuorumStatus()
	names := make([]string, 0, len(st.Custodians))
	for _, c := range st.Custodians {
		names = append(names, c.Name)
	}
	detail := fmt.Sprintf("mode %s, seuil %d sur %d (%s), KEK génération %d", st.Mode, st.Threshold, len(names), strings.Join(names, ", "), st.Current)
	if len(names) == 0 {
		detail = fmt.Sprintf("quorum supprimé, mode auto, KEK génération %d", st.Current)
	}
	a.record(user, "quorum.reconfiguré", detail)

	// Révocation : données rechiffrées par la KEK neuve, puis destruction des
	// générations remplacées, sous l'autorité du quorum qui vient d'approuver.
	out := map[string]any{}
	if _, err := a.rewrapAll(r.Context(), user, false); err != nil {
		a.record(user, "kek.réchiffrement-échec", err.Error())
		out["rewrap_error"] = err.Error()
	} else {
		gone, left, err := a.purgeSuperseded(user)
		if err != nil {
			out["purge_error"] = err.Error()
		}
		out["destroyed"], out["left"] = gone, left
	}
	out["status"] = sw.QuorumStatus()
	writeJSON(w, out)
}

// rotationReport résume une rotation ou un réchiffrement.
type rotationReport struct {
	Gen      uint32              `json:"gen"`
	Keys     int                 `json:"keys"`
	QueryLog int                 `json:"querylog"`
	Retired  []uint32            `json:"retired"`
	Pending  map[uint32][]string `json:"pending"` // fichiers encore chiffrés par une ancienne génération
}

// purgeSuperseded détruit les générations remplacées par la dernière
// reconfiguration, sous le verrou des rotations et après un inventaire
// frais : une écriture achevée entre-temps sur une ancienne génération
// l'empêche, comme pour une destruction ordinaire.
func (a *API) purgeSuperseded(user string) (gone, left []uint32, err error) {
	sw, ok := a.KS.(*keystore.Software)
	if !ok {
		return nil, nil, nil
	}
	a.quorum.rot.Lock()
	defer a.quorum.rot.Unlock()
	inv, err := migrate.Inventory(a.DataDir, sw.Dir())
	if err != nil {
		a.record(user, "kek.destruction-échec", err.Error())
		return nil, nil, err
	}
	inUse := map[uint32]bool{}
	for g := range inv {
		inUse[g] = true
	}
	gone, left, err = sw.PurgeSuperseded(inUse)
	if err != nil {
		a.record(user, "kek.destruction-échec", err.Error())
	}
	if len(gone) > 0 {
		a.record(user, "kek.détruite", fmt.Sprintf("générations %v remplacées par la reconfiguration (effacement cryptographique)", gone))
	}
	return gone, left, err
}

// RotateKEK crée une KEK neuve puis réchiffre les données. Appelée depuis
// l'interface et par la rotation planifiée.
func (a *API) RotateKEK(ctx context.Context, user string) (rotationReport, error) {
	return a.rewrapAll(ctx, user, true)
}

func (a *API) rewrapAll(_ context.Context, user string, rotate bool) (rotationReport, error) {
	var rep rotationReport
	sw, ok := a.KS.(*keystore.Software)
	if !ok {
		return rep, errors.New("keystore HSM : la rotation de la KEK se fait sur le HSM")
	}
	a.quorum.rot.Lock()
	defer a.quorum.rot.Unlock()
	if rotate {
		gen, err := sw.RotateKEK()
		if err != nil {
			return rep, err
		}
		a.record(user, "kek.rotation", fmt.Sprintf("génération %d en service", gen))
	}
	rep.Gen = sw.QuorumStatus().Current
	var err error
	if rep.Keys, err = sw.RewrapKeys(); err != nil {
		return rep, fmt.Errorf("clés de signature : %w", err)
	}
	// L'état et la tête d'audit sont réécrits par leurs propriétaires, sous
	// leurs propres verrous : jamais de renommage concurrent d'une écriture.
	if err := a.Store.Update(func(*state.State) error { return nil }); err != nil {
		return rep, fmt.Errorf("état : %w", err)
	}
	if a.DHCP != nil {
		if err := a.DHCP.Flush(); err != nil {
			return rep, fmt.Errorf("baux DHCP : %w", err)
		}
	}
	for _, reseal := range a.Resealers {
		if err := reseal(); err != nil {
			return rep, fmt.Errorf("copies scellées : %w", err)
		}
	}
	if rep.QueryLog, err = migrate.RewrapQueryLogKeys(a.DataDir, sw); err != nil {
		return rep, fmt.Errorf("journal : %w", err)
	}
	a.record(user, "kek.réchiffrement", fmt.Sprintf("génération %d : %d clé(s) de signature, %d clé(s) du journal", rep.Gen, rep.Keys, rep.QueryLog))
	inv, err := migrate.Inventory(a.DataDir, sw.Dir())
	if err != nil {
		return rep, fmt.Errorf("inventaire (aucune génération retirée) : %w", err)
	}
	inUse := map[uint32]bool{}
	rep.Pending = map[uint32][]string{}
	for g, files := range inv {
		inUse[g] = true
		if g != rep.Gen {
			rep.Pending[g] = files
		}
	}
	if rep.Retired, err = sw.RetireGenerations(inUse); err != nil {
		return rep, err
	}
	if len(rep.Retired) > 0 {
		a.record(user, "kek.retirée", fmt.Sprint(rep.Retired))
	}
	return rep, nil
}

func (a *API) kekRotate(w http.ResponseWriter, r *http.Request, user string) {
	if _, ok := a.software(w); !ok {
		return
	}
	var in struct {
		Password string
		Rotate   bool
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !CheckPassword(in.Password, a.Store.Get().Admin.PasswordHash) {
		jsonError(w, http.StatusForbidden, "mot de passe administrateur incorrect")
		return
	}
	rep, err := a.rewrapAll(r.Context(), user, in.Rotate)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, rep)
}

func (a *API) kekDestroy(w http.ResponseWriter, r *http.Request, user string) {
	sw, ok := a.software(w)
	if !ok {
		return
	}
	var in struct {
		OpID     string `json:"op_id"`
		Password string
		Gen      uint32
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !CheckPassword(in.Password, a.Store.Get().Admin.PasswordHash) {
		jsonError(w, http.StatusForbidden, "mot de passe administrateur incorrect")
		return
	}
	approval, _, err := a.takeApproval(sw, in.OpID, "destroy", func(op *quorumOp) bool { return op.Gen == in.Gen })
	if err != nil {
		jsonError(w, http.StatusForbidden, err.Error())
		return
	}
	defer keystore.WipeShares(approval)
	// Dernier contrôle juste avant l'effacement, sans rotation concurrente :
	// une donnée écrite depuis le retrait de la génération l'empêche.
	a.quorum.rot.Lock()
	defer a.quorum.rot.Unlock()
	inv, err := migrate.Inventory(a.DataDir, sw.Dir())
	if err != nil {
		jsonError(w, http.StatusConflict, "inventaire impossible, destruction refusée : "+err.Error())
		return
	}
	if files := inv[in.Gen]; len(files) > 0 {
		jsonError(w, http.StatusConflict, fmt.Sprintf("la génération %d chiffre encore %s : réchiffrez d'abord", in.Gen, strings.Join(files, ", ")))
		return
	}
	if err := sw.DestroyGeneration(in.Gen, approval); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.record(user, "kek.détruite", fmt.Sprintf("génération %d (effacement cryptographique)", in.Gen))
	a.quorumStatus(w, r, user)
}

func (a *API) kekPolicy(w http.ResponseWriter, r *http.Request, user string) {
	sw, ok := a.software(w)
	if !ok {
		return
	}
	var in struct {
		OpID     string `json:"op_id"`
		Password string
		Days     int
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !CheckPassword(in.Password, a.Store.Get().Admin.PasswordHash) {
		jsonError(w, http.StatusForbidden, "mot de passe administrateur incorrect")
		return
	}
	approval, _, err := a.takeApproval(sw, in.OpID, "policy", func(op *quorumOp) bool { return op.Days == in.Days })
	if err != nil {
		jsonError(w, http.StatusForbidden, err.Error())
		return
	}
	defer keystore.WipeShares(approval)
	if err := sw.SetRotation(in.Days, approval); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.record(user, "kek.politique", describeOp("policy", 0, in.Days))
	a.quorumStatus(w, r, user)
}

// KeyMaintenance déclenche la rotation planifiée quand elle est due, et
// rechiffre les données restées sur une génération non retirée (après la
// conversion d'un ancien keystore, ou un réchiffrement interrompu).
func (a *API) KeyMaintenance(ctx context.Context) error {
	sw, ok := a.KS.(*keystore.Software)
	if !ok {
		return nil
	}
	if sw.RotationDue(time.Now()) {
		_, err := a.RotateKEK(ctx, "système")
		return err
	}
	st := sw.QuorumStatus()
	for _, g := range st.Generations {
		if !g.Current && g.Retired == nil {
			if _, err := a.rewrapAll(ctx, "système", false); err != nil {
				return err
			}
			break
		}
	}
	// Générations remplacées au démarrage (phrase serveur ajoutée à un
	// keystore qui n'en avait pas) : détruites une fois les données rechiffrées.
	_, _, err := a.purgeSuperseded("système")
	return err
}
