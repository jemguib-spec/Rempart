package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/sealed"
)

// Report : résultat d'une vérification approfondie.
type Report struct {
	Manifest   Manifest `json:"manifest"`
	Files      int      `json:"files"`
	Keystore   string   `json:"keystore"`
	State      string   `json:"state"`
	Audit      string   `json:"audit"`
	Sealed     int      `json:"sealed_ok"`
	SealedFail []string `json:"sealed_fail,omitempty"`
}

// Verify ouvre une extraction (Extract) avec la phrase de passe et vérifie
// que l'état et chaque fichier scellé se déchiffrent, et que le journal
// d'audit est intact. Rien n'est modifié hors du dossier extrait.
func Verify(extracted, passphrase string, m Manifest) (Report, error) {
	rep := Report{Manifest: m, Files: len(m.Files)}
	if m.Backend != "software" {
		rep.Keystore = "HSM : les clés ne sont pas dans l'archive, vérifiez sur un serveur relié au token"
		return rep, nil
	}
	ksDir := filepath.Join(extracted, "keystore")
	ks, warn, err := keystore.OpenSoftware(ksDir, passphrase)
	if errors.Is(err, keystore.ErrQuorumRequired) {
		rep.Keystore = "démarrage sous quorum : le contenu ne peut être vérifié qu'avec les dépositaires (empreintes vérifiées)"
		return rep, nil
	}
	if err != nil {
		return rep, fmt.Errorf("keystore de l'archive : %w", err)
	}
	defer ks.Close()
	rep.Keystore = "ouvert (" + ks.Describe() + ")"
	if warn != "" {
		rep.Keystore += " ; " + warn
	}
	data := filepath.Join(extracted, "data")
	raw, err := sealed.ReadFile(ks, filepath.Join(data, "state.sealed"))
	if err != nil {
		return rep, fmt.Errorf("état : %w", err)
	}
	var st map[string]json.RawMessage
	if err := json.Unmarshal(raw, &st); err != nil {
		return rep, fmt.Errorf("état : %w", err)
	}
	rep.State = fmt.Sprintf("lisible (%d sections)", len(st))
	entries, _ := os.ReadDir(data)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".sealed" && filepath.Ext(e.Name()) != ".head" {
			continue
		}
		blob, err := os.ReadFile(filepath.Join(data, e.Name()))
		if err != nil || !sealed.IsSealed(blob) {
			continue
		}
		if _, err := sealed.Open(ks, blob, sealed.FileAAD(filepath.Join(data, e.Name()))); err != nil {
			rep.SealedFail = append(rep.SealedFail, e.Name())
			continue
		}
		rep.Sealed++
	}
	al, err := audit.Open(ks, data)
	if err != nil {
		return rep, fmt.Errorf("audit : %w", err)
	}
	if v := al.Verify(); v.OK {
		rep.Audit = fmt.Sprintf("intègre (%d événements)", v.Count)
	} else {
		rep.Audit = "ALTÉRÉ : " + v.Problem
	}
	if len(rep.SealedFail) > 0 {
		return rep, fmt.Errorf("%d fichier(s) scellé(s) indéchiffrable(s)", len(rep.SealedFail))
	}
	return rep, nil
}
