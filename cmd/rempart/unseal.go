// unseal.go - démarrage verrouillé (mode quorum) et commande « rempart unseal » des dépositaires.
// Le serveur attend les phrases sur un socket Unix 0600 du dossier du keystore ;
// le client les lit au terminal sans écho. Rempart ; aucune phrase en argument ni dans les journaux.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rempart-dns/rempart/internal/config"
	"github.com/rempart-dns/rempart/internal/keystore"
)

type unsealReq struct {
	Name       string `json:"name,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type unsealResp struct {
	OK     bool     `json:"ok"`
	Error  string   `json:"error,omitempty"`
	Have   []string `json:"have"`
	Need   int      `json:"need"`
	Opened bool     `json:"opened"`
}

func unsealSocket(cfg *config.Config) string {
	return filepath.Join(cfg.Keystore.Software.Dir, "unseal.sock")
}

// waitUnseal bloque jusqu'à ce que le quorum ait déverrouillé le keystore.
// Il renvoie aussi les noms des dépositaires présentés, pour l'audit.
func waitUnseal(cfg *config.Config, log *slog.Logger) (*keystore.Software, []string, error) {
	u, err := keystore.NewUnsealer(cfg.Keystore.Software.Dir)
	if err != nil {
		return nil, nil, err
	}
	path := unsealSocket(cfg)
	_ = os.Remove(path)
	old := umask(0o177) // socket créé directement en 0600
	ln, err := net.Listen("unix", path)
	umask(old)
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(path)
	defer ln.Close()
	_ = os.Chmod(path, 0o600)
	log.Warn("KEYSTORE VERROUILLÉ : en attente du quorum des dépositaires, aucun service DNS tant qu'il n'est pas atteint",
		"seuil", u.Need(), "commande", "podman exec -it <conteneur> rempart unseal")

	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil, nil, err
		}
		if err := checkPeer(conn); err != nil {
			log.Warn("connexion de déverrouillage refusée", "err", err)
			conn.Close()
			continue
		}
		// Une connexion à la fois : Argon2id est sérialisé de toute façon.
		if ks, names := serveUnseal(conn, u, log); ks != nil {
			return ks, names, nil
		}
	}
}

func serveUnseal(conn net.Conn, u *keystore.Unsealer, log *slog.Logger) (*keystore.Software, []string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	sc := bufio.NewScanner(io.LimitReader(conn, 64<<10))
	enc := json.NewEncoder(conn)
	for sc.Scan() {
		var req unsealReq
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			_ = enc.Encode(unsealResp{Error: "requête invalide"})
			return nil, nil
		}
		names, need := u.Progress()
		if req.Name == "" { // simple demande d'état
			_ = enc.Encode(unsealResp{OK: true, Have: names, Need: need})
			continue
		}
		_, ks, err := u.Add(req.Name, req.Passphrase)
		req.Passphrase = ""
		if err != nil {
			log.Warn("déverrouillage : part refusée") // nom saisi non journalisé : ce peut être une phrase tapée au mauvais endroit
			_ = enc.Encode(unsealResp{Error: err.Error(), Have: names, Need: need})
			continue
		}
		if ks != nil {
			all := append(names, req.Name)
			log.Info("keystore déverrouillé par le quorum", "dépositaires", strings.Join(all, ", "))
			_ = enc.Encode(unsealResp{OK: true, Opened: true, Have: all, Need: need})
			return ks, all
		}
		names, _ = u.Progress()
		log.Info("déverrouillage : part acceptée", "présentés", len(names), "seuil", need)
		_ = enc.Encode(unsealResp{OK: true, Have: names, Need: need})
	}
	return nil, nil
}

// cmdUnseal : client lancé par chaque dépositaire, par exemple
// « podman exec -it rempart rempart unseal ».
func cmdUnseal(args []string) int {
	fs := flag.NewFlagSet("unseal", flag.ExitOnError)
	cfgPath := fs.String("config", envOr("REMPART_CONFIG", "/etc/rempart/rempart.yaml"), "fichier de configuration YAML")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	conn, err := net.Dial("unix", unsealSocket(cfg))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Rempart n'attend pas de déverrouillage (socket absent) :", err)
		return 1
	}
	defer conn.Close()
	enc, dec := json.NewEncoder(conn), json.NewDecoder(conn)
	var st unsealResp
	if enc.Encode(unsealReq{}) != nil || dec.Decode(&st) != nil {
		fmt.Fprintln(os.Stderr, "dialogue impossible avec Rempart")
		return 1
	}
	fmt.Printf("Keystore verrouillé : %d dépositaire(s) sur %d présenté(s)%s\n", len(st.Have), st.Need, listNames(st.Have))
	in := bufio.NewReader(os.Stdin)
	fmt.Print("Dépositaire : ")
	name, _ := in.ReadString('\n')
	name = strings.TrimSpace(name)
	pass, err := readSecret(in, "Phrase de passe : ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("Vérification (Argon2id, quelques secondes)…")
	err = enc.Encode(unsealReq{Name: name, Passphrase: pass})
	pass = ""
	if err != nil || dec.Decode(&st) != nil {
		fmt.Fprintln(os.Stderr, "dialogue impossible avec Rempart")
		return 1
	}
	switch {
	case st.Error != "":
		fmt.Fprintln(os.Stderr, "Refusé :", st.Error)
		return 1
	case st.Opened:
		fmt.Println("Quorum atteint : keystore déverrouillé, Rempart démarre.")
	default:
		fmt.Printf("Part acceptée : %d sur %d%s. Dépositaire suivant : relancez la commande.\n", len(st.Have), st.Need, listNames(st.Have))
	}
	return 0
}

func listNames(n []string) string {
	if len(n) == 0 {
		return ""
	}
	return " (" + strings.Join(n, ", ") + ")"
}
