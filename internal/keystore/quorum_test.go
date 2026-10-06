// quorum_test.go - tests du keystore v2 : Shamir, cérémonie, rotation, déverrouillage, migration v1.
// Exécution : go test ./internal/keystore/ (Argon2id réel, quelques secondes).
// Rempart ; aucun secret de production, phrases de passe de test seulement.

package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func TestShamirAllSubsets(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	shares, err := shamirSplit(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	for a := 0; a < 5; a++ {
		for b := a + 1; b < 5; b++ {
			// Deux parts sur trois requises : résultat faux.
			if got, _ := shamirCombine([]Share{shares[a], shares[b]}); bytes.Equal(got, secret) {
				t.Fatal("deux parts suffisent à reconstituer le secret")
			}
			for c := b + 1; c < 5; c++ {
				got, err := shamirCombine([]Share{shares[c], shares[a], shares[b]})
				if err != nil || !bytes.Equal(got, secret) {
					t.Fatalf("parts %d,%d,%d : secret non reconstitué", a, b, c)
				}
			}
		}
	}
	if _, err := shamirCombine([]Share{shares[0], shares[0]}); err == nil {
		t.Fatal("part en double acceptée")
	}
	if _, err := shamirSplit(secret, 3, 1); err == nil {
		t.Fatal("seuil de 1 accepté")
	}
	// Inverse multiplicatif sur tout le corps.
	for a := 1; a < 256; a++ {
		if gf256Mul(byte(a), gf256Inv(byte(a))) != 1 {
			t.Fatalf("inverse de %d faux", a)
		}
	}
}

var team = []NewCustodian{
	{Name: "Alice", Passphrase: "alice-phrase-de-passe"},
	{Name: "Bruno", Passphrase: "bruno-phrase-de-passe"},
	{Name: "Chloé", Passphrase: "chloe-phrase-de-passe"},
}

func approve(t *testing.T, s *Software, who ...int) []Share {
	t.Helper()
	var out []Share
	for _, i := range who {
		sh, _, err := s.OpenShare(team[i].Name, team[i].Passphrase)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, sh)
	}
	return out
}

func TestQuorumLifecycle(t *testing.T) {
	dir := t.TempDir()
	s, _, err := OpenSoftware(dir, "phrase-serveur")
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := s.Wrap([]byte("donnée"), []byte("aad"))
	if _, err := s.Signer("k1", ECDSAP256, true); err != nil {
		t.Fatal(err)
	}

	// Première cérémonie : 2 sur 3, mode auto, sans approbation préalable.
	if err := s.Reconfigure(Reconfig{Mode: ModeAuto, Threshold: 2, Custodians: team}, nil); err != nil {
		t.Fatal(err)
	}
	if !s.QuorumRequired() {
		t.Fatal("quorum non actif")
	}
	if err := s.SetRotation(30, nil); err == nil {
		t.Fatal("opération sensible acceptée sans quorum")
	}
	if err := s.SetRotation(30, approve(t, s, 0)); err == nil {
		t.Fatal("une seule approbation acceptée pour un seuil de 2")
	}
	if _, _, err := s.OpenShare("Alice", "mauvaise-phrase-123"); err == nil {
		t.Fatal("mauvaise phrase de dépositaire acceptée")
	}
	if err := s.SetRotation(30, approve(t, s, 0, 2)); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// Redémarrage en mode auto : la phrase serveur suffit, les données restent lisibles.
	s, _, err = OpenSoftware(dir, "phrase-serveur")
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := s.Unwrap(ct, []byte("aad")); err != nil || string(pt) != "donnée" {
		t.Fatal("donnée illisible après reconfiguration", err)
	}
	if s.QuorumStatus().RotateDays != 30 {
		t.Fatal("période de rotation non enregistrée")
	}
	// Sans phrase serveur, seul le quorum ouvre (secours).
	if _, _, err := OpenSoftware(dir, ""); !errors.Is(err, ErrQuorumRequired) {
		t.Fatalf("sans phrase serveur : %v", err)
	}

	// Passage en mode quorum au démarrage, avec les anciennes parts.
	old := approve(t, s, 1, 2)
	if err := s.Reconfigure(Reconfig{Mode: ModeQuorum, Threshold: 2, Custodians: team}, old); err != nil {
		t.Fatal(err)
	}
	if s.QuorumStatus().ServerPass != "" {
		t.Fatal("la phrase serveur protège encore la clé racine en mode quorum")
	}
	// Les parts de l'ancienne clé racine ne valent plus rien.
	if err := s.SetRotation(10, old); err == nil {
		t.Fatal("parts d'une ancienne clé racine acceptées")
	}
	ct2, _ := s.Wrap([]byte("après"), nil)
	s.Close()

	if _, _, err := OpenSoftware(dir, "phrase-serveur"); !errors.Is(err, ErrQuorumRequired) {
		t.Fatalf("mode quorum ouvert par la phrase serveur : %v", err)
	}
	u, err := NewUnsealer(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n, ks, err := u.Add("alice", team[0].Passphrase); err != nil || ks != nil || n != 1 {
		t.Fatalf("première part : %d %v %v", n, ks, err)
	}
	if _, _, err := u.Add("Bruno", "fausse-phrase-bruno"); err == nil {
		t.Fatal("fausse phrase acceptée au déverrouillage")
	}
	_, s, err = u.Add("Chloé", team[2].Passphrase)
	if err != nil || s == nil {
		t.Fatal("déverrouillage", err)
	}
	if pt, err := s.Unwrap(ct2, nil); err != nil || string(pt) != "après" {
		t.Fatal("génération courante illisible après déverrouillage", err)
	}
	if pt, err := s.Unwrap(ct, []byte("aad")); err != nil || string(pt) != "donnée" {
		t.Fatal("ancienne génération illisible", err)
	}
	s.Close()
}

func TestRotationAndDestroy(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := OpenSoftware(dir, "phrase-serveur")
	old, _ := s.Wrap([]byte("x"), nil)
	k1, _ := s.Signer("k1", ECDSAP256, true)
	g, err := s.RotateKEK()
	if err != nil || g != 2 {
		t.Fatal(g, err)
	}
	if s.IsCurrent(old) {
		t.Fatal("bloc ancien vu comme courant")
	}
	if n, err := s.RewrapKeys(); err != nil || n != 1 {
		t.Fatal("réchiffrement des clés", n, err)
	}
	if err := s.DestroyGeneration(1, nil); err == nil {
		t.Fatal("génération encore utilisée détruite")
	}
	if done, err := s.RetireGenerations(map[uint32]bool{}); err != nil || len(done) != 1 {
		t.Fatal(done, err)
	}
	if err := s.DestroyGeneration(2, nil); err == nil {
		t.Fatal("génération courante détruite")
	}
	if err := s.DestroyGeneration(1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unwrap(old, nil); err == nil {
		t.Fatal("donnée de la génération détruite encore lisible")
	}
	s.Close()
	s, _, err = OpenSoftware(dir, "phrase-serveur")
	if err != nil {
		t.Fatal(err)
	}
	k, err := s.Signer("k1", "", false)
	if err != nil || Fingerprint(k.Public()) != Fingerprint(k1.Public()) {
		t.Fatal("clé de signature perdue après rotation", err)
	}
	if !s.RotationDue(time.Now().AddDate(1, 0, 1)) || s.RotationDue(time.Now()) {
		t.Fatal("échéance de rotation fausse")
	}
}

func TestMasterTamper(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := OpenSoftware(dir, "phrase-serveur")
	s.Close()
	raw, _ := os.ReadFile(masterPath(dir))
	bad := strings.Replace(string(raw), `"rotate_days":365`, `"rotate_days":0`, 1)
	if bad == string(raw) {
		t.Fatal("motif introuvable")
	}
	_ = os.WriteFile(masterPath(dir), []byte(bad), 0o600)
	if _, _, err := OpenSoftware(dir, "phrase-serveur"); err == nil {
		t.Fatal("master.json modifié accepté")
	}
	// Paramètres Argon2id absurdes, lus avant le contrôle d'intégrité : erreur, pas de panique.
	evil := strings.Replace(string(raw), `"t":3`, `"t":0`, 1)
	_ = os.WriteFile(masterPath(dir), []byte(evil), 0o600)
	if _, _, err := OpenSoftware(dir, "phrase-serveur"); err == nil || !strings.Contains(err.Error(), "hors bornes") {
		t.Fatalf("paramètres Argon2id hors bornes : %v", err)
	}
}

// Un dépositaire conservé prouve sa phrase : impossible de lui en imposer une autre.
func TestKeepCustodian(t *testing.T) {
	s, _, _ := OpenSoftware(t.TempDir(), "phrase-serveur")
	defer s.Close()
	if err := s.Reconfigure(Reconfig{Mode: ModeAuto, Threshold: 2, Custodians: team}, nil); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, c := range s.QuorumStatus().Custodians {
		ids[c.Name] = c.ID
	}
	_, proofA, _, err := s.OpenShareRekey("Alice", team[0].Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	next := []NewCustodian{{KeepID: ids["Alice"], Proof: proofA}, {KeepID: ids["Bruno"], Passphrase: "phrase-imposee-par-admin"}, {Name: "Damien", Passphrase: "damien-phrase-xx"}}
	if err := s.Reconfigure(Reconfig{Mode: ModeAuto, Threshold: 2, Custodians: next}, approve(t, s, 0, 2)); err == nil {
		t.Fatal("phrase imposée à un dépositaire conservé acceptée")
	}
	next[1].Passphrase = team[1].Passphrase
	_, next[0].Proof, _, _ = s.OpenShareRekey("Alice", team[0].Passphrase)
	if err := s.Reconfigure(Reconfig{Mode: ModeAuto, Threshold: 2, Custodians: next}, approve(t, s, 0, 2)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.OpenShare("Bruno", team[1].Passphrase); err != nil {
		t.Fatal("Bruno a perdu sa phrase", err)
	}
	if _, _, err := s.OpenShare("Chloé", team[2].Passphrase); err == nil {
		t.Fatal("dépositaire retiré encore accepté")
	}
	if err := s.CheckQuorum(func() []Share {
		a, _, _ := s.OpenShare("Alice", team[0].Passphrase)
		d, _, _ := s.OpenShare("Damien", "damien-phrase-xx")
		return []Share{a, d}
	}()); err != nil {
		t.Fatal("nouveau quorum inopérant", err)
	}
}

// Keystore v1 écrit comme le faisait la version précédente.
func TestUpgradeFromV1(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "keys"), 0o700)
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	master := argon2.IDKey([]byte("ancienne-phrase"), salt, 3, 64*1024, 2, 32)
	b, _ := aes.NewCipher(master)
	a, _ := cipher.NewGCM(b)
	v1wrap := func(pt, aad []byte) []byte {
		n := make([]byte, a.NonceSize())
		_, _ = rand.Read(n)
		return a.Seal(append([]byte{1}, n...), n, pt, aad)
	}
	mf, _ := json.Marshal(legacyMaster{KDF: "argon2id", Salt: base64.StdEncoding.EncodeToString(salt), Time: 3, Memory: 64 * 1024, Thread: 2,
		Check: base64.StdEncoding.EncodeToString(v1wrap([]byte("rempart"), []byte("check")))})
	_ = os.WriteFile(masterPath(dir), mf, 0o600)
	old := v1wrap([]byte("état"), []byte("state"))

	if _, _, err := OpenSoftware(dir, "mauvaise"); err == nil {
		t.Fatal("mauvaise phrase acceptée lors de la migration v1")
	}
	s, _, err := OpenSoftware(dir, "ancienne-phrase")
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := s.Unwrap(old, []byte("state")); err != nil || string(pt) != "état" {
		t.Fatal("donnée v1 illisible", err)
	}
	st := s.QuorumStatus()
	if st.Current != 1 || len(st.Generations) != 2 || !st.Generations[1].Legacy {
		t.Fatalf("après conversion, la génération 1 doit être en service : %+v", st)
	}
	if nw, _ := s.Wrap([]byte("x"), nil); !s.IsCurrent(nw) || nw[0] != 2 {
		t.Fatal("les nouvelles données doivent utiliser la génération 1")
	}
	s.Close()
	if s, _, err = OpenSoftware(dir, "ancienne-phrase"); err != nil {
		t.Fatal("réouverture après migration", err)
	}
	_, _ = s.RetireGenerations(map[uint32]bool{})
	if err := s.DestroyGeneration(0, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(masterPath(dir) + ".v1"); !os.IsNotExist(err) {
		t.Fatal("master.json.v1 conservé après destruction de la génération 0")
	}
}

// Constats de la relecture : noms piégés, révocation effective après reconfiguration.
func TestCustodianNames(t *testing.T) {
	for _, bad := range []string{"Damien\x00Eve", "Eve\u200b", "Zoe\u0301", " Alice", "a1b2c3d4", "", strings.Repeat("x", 65), "x\ny"} {
		if ValidCustodianName(bad) == nil {
			t.Errorf("nom %q accepté", bad)
		}
	}
	for _, good := range []string{"Alice", "Chloé", "Jean-Marc O'Neil", "PKI_2", "Zoé.L"} {
		if err := ValidCustodianName(good); err != nil {
			t.Errorf("nom %q refusé : %v", good, err)
		}
	}
}

func TestReconfigureRevokes(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := OpenSoftware(dir, "phrase-serveur")
	defer s.Close()
	if err := s.Reconfigure(Reconfig{Mode: ModeAuto, Threshold: 2, Custodians: team}, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(masterPath(dir)) // sauvegarde volée avant le retrait de Chloé
	ids := map[string]string{}
	for _, c := range s.QuorumStatus().Custodians {
		ids[c.Name] = c.ID
	}
	_, pa, _, _ := s.OpenShareRekey("Alice", team[0].Passphrase)
	_, pb, _, _ := s.OpenShareRekey("Bruno", team[1].Passphrase)
	next := []NewCustodian{{KeepID: ids["Alice"], Proof: pa}, {KeepID: ids["Bruno"], Proof: pb}}
	if err := s.Reconfigure(Reconfig{Mode: ModeAuto, Threshold: 2, Custodians: next}, approve(t, s, 0, 1)); err != nil {
		t.Fatal(err)
	}
	secret, _ := s.Wrap([]byte("après-reconfiguration"), nil)
	// Rien n'utilise plus les anciennes générations : elles sont détruites.
	gone, left, err := s.PurgeSuperseded(map[uint32]bool{s.QuorumStatus().Current: true})
	if err != nil || len(gone) == 0 || len(left) != 0 {
		t.Fatalf("purge : %v %v %v", gone, left, err)
	}

	// L'ancien master.json, même avec les phrases de Chloé et Bruno, ne lit pas la donnée récente.
	odir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(odir, "keys"), 0o700)
	_ = os.WriteFile(masterPath(odir), before, 0o600)
	u, err := NewUnsealer(odir)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = u.Add("Bruno", team[1].Passphrase)
	_, old, err := u.Add("Chloé", team[2].Passphrase)
	if err != nil || old == nil {
		t.Fatal("l'ancien fichier devrait encore s'ouvrir", err)
	}
	if _, err := old.Unwrap(secret, nil); err == nil {
		t.Fatal("un ancien master.json déchiffre une donnée écrite après la reconfiguration")
	}
	old.Close()
	// La phrase serveur seule, sur l'ancien fichier, non plus.
	o2, _, err := OpenSoftware(odir, "phrase-serveur")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o2.Unwrap(secret, nil); err == nil {
		t.Fatal("ancien fichier + phrase serveur déchiffrent une donnée récente")
	}
	o2.Close()
	// Un nom qui ressemble à un identifiant ne peut pas masquer un dépositaire.
	bad := []NewCustodian{{KeepID: ids["Alice"], Passphrase: team[0].Passphrase}, {Name: ids["Bruno"], Passphrase: "phrase-de-vingt-car"}}
	if err := s.Reconfigure(Reconfig{Mode: ModeAuto, Threshold: 2, Custodians: bad}, approve(t, s, 0, 1)); err == nil {
		t.Fatal("nom en forme d'identifiant accepté")
	}
}
