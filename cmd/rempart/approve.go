// approve.go - approbation des opérations du quorum au terminal du serveur (« rempart approve »).
// Socket Unix 0600 du dossier du keystore, ouvert pendant le service ; la phrase du dépositaire
// ne passe ni par le navigateur de l'administrateur, ni par la ligne de commande, ni par les journaux.

package main

import (
	"bufio"
	"context"
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

	"github.com/rempart-dns/rempart/internal/api"
	"github.com/rempart-dns/rempart/internal/config"
)

// approveReq : demande sur le socket d'approbation. Action vide : approuver
// l'opération OpID (ou, sans nom, la décrire) ; "passwd" : changer sa phrase.
type approveReq struct {
	Action     string `json:"action,omitempty"`
	OpID       string `json:"op_id,omitempty"`
	Name       string `json:"name,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	New        string `json:"new,omitempty"`
}

type approveResp struct {
	OK          bool     `json:"ok"`
	Error       string   `json:"error,omitempty"`
	OpID        string   `json:"op_id,omitempty"`
	Description string   `json:"description,omitempty"`
	ApprovedBy  []string `json:"approved_by,omitempty"`
	Approved    int      `json:"approved"`
	Need        int      `json:"need"`
}

func approveSocket(cfg *config.Config) string {
	return filepath.Join(cfg.Keystore.Software.Dir, "approve.sock")
}

// serveApprovals écoute les approbations des dépositaires tant que Rempart tourne.
func serveApprovals(ctx context.Context, cfg *config.Config, a *api.API, log *slog.Logger) {
	path := approveSocket(cfg)
	_ = os.Remove(path)
	old := umask(0o177)
	ln, err := net.Listen("unix", path)
	umask(old)
	if err != nil {
		log.Error("socket d'approbation du quorum indisponible", "err", err)
		return
	}
	_ = os.Chmod(path, 0o600)
	go func() { <-ctx.Done(); ln.Close(); _ = os.Remove(path) }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if err := checkPeer(conn); err != nil {
			log.Warn("connexion d'approbation refusée", "err", err)
			conn.Close()
			continue
		}
		handleApprove(conn, a) // une à la fois : Argon2id est sérialisé de toute façon
	}
}

func handleApprove(conn net.Conn, a *api.API) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	sc := bufio.NewScanner(io.LimitReader(conn, 64<<10))
	enc := json.NewEncoder(conn)
	for sc.Scan() {
		var req approveReq
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			_ = enc.Encode(approveResp{Error: "requête invalide"})
			return
		}
		if req.Action == "passwd" {
			err := a.TerminalPasswd(req.Name, req.Passphrase, req.New)
			req.Passphrase, req.New = "", ""
			resp := approveResp{OK: err == nil}
			if err != nil {
				resp.Error = err.Error()
			}
			_ = enc.Encode(resp)
			continue
		}
		op, err := a.TerminalApprove(req.OpID, req.Name, req.Passphrase)
		req.Passphrase = ""
		resp := approveResp{OK: err == nil}
		if err != nil {
			resp.Error = err.Error()
		}
		if op != nil {
			resp.OpID, _ = op["id"].(string)
			resp.Description, _ = op["description"].(string)
			resp.ApprovedBy, _ = op["approved_by"].([]string)
			resp.Approved, _ = op["approved"].(int)
			resp.Need, _ = op["need"].(int)
		}
		_ = enc.Encode(resp)
	}
}

// cmdApprove : client d'un dépositaire, par exemple « podman exec -it rempart rempart approve ».
func cmdApprove(args []string) int {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	cfgPath := fs.String("config", envOr("REMPART_CONFIG", "/etc/rempart/rempart.yaml"), "fichier de configuration YAML")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	conn, err := net.Dial("unix", approveSocket(cfg))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Rempart ne reçoit pas d'approbation (socket absent) :", err)
		return 1
	}
	defer conn.Close()
	enc, dec := json.NewEncoder(conn), json.NewDecoder(conn)
	var st approveResp
	if enc.Encode(approveReq{}) != nil || dec.Decode(&st) != nil {
		fmt.Fprintln(os.Stderr, "dialogue impossible avec Rempart")
		return 1
	}
	if st.Error != "" {
		fmt.Fprintln(os.Stderr, st.Error)
		return 1
	}
	// Le dépositaire lit ici, sur le serveur, ce qu'il approuve exactement.
	fmt.Printf("Opération en attente : %s\nApprobations : %d sur %d%s\n", st.Description, len(st.ApprovedBy), st.Need, listNames(st.ApprovedBy))
	in := bufio.NewReader(os.Stdin)
	fmt.Print("Approuver ? Dépositaire (vide pour abandonner) : ")
	name, _ := in.ReadString('\n')
	if name = strings.TrimSpace(name); name == "" {
		return 0
	}
	pass, err := readSecret(in, "Phrase de passe : ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("Vérification (Argon2id, quelques secondes)…")
	shown := st.Description
	err = enc.Encode(approveReq{OpID: st.OpID, Name: name, Passphrase: pass})
	pass = ""
	if err != nil || dec.Decode(&st) != nil {
		fmt.Fprintln(os.Stderr, "dialogue impossible avec Rempart")
		return 1
	}
	if st.Error != "" {
		fmt.Fprintln(os.Stderr, "Refusé :", st.Error)
		return 1
	}
	fmt.Printf("Approbation enregistrée (%d sur %d) pour : %s\n", st.Approved, st.Need, shown)
	return 0
}

// cmdPasswd : un dépositaire fixe lui-même sa phrase, sur le serveur
// (« podman exec -it rempart rempart passwd »). Indispensable en mode
// « approbations au terminal seulement ».
func cmdPasswd(args []string) int {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	cfgPath := fs.String("config", envOr("REMPART_CONFIG", "/etc/rempart/rempart.yaml"), "fichier de configuration YAML")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	conn, err := net.Dial("unix", approveSocket(cfg))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Rempart ne répond pas sur le socket d'approbation :", err)
		return 1
	}
	defer conn.Close()
	in := bufio.NewReader(os.Stdin)
	fmt.Print("Dépositaire : ")
	name, _ := in.ReadString('\n')
	name = strings.TrimSpace(name)
	cur, err := readSecret(in, "Phrase actuelle : ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	n1, err := readSecret(in, "Nouvelle phrase (12 caractères au moins) : ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	n2, err := readSecret(in, "Nouvelle phrase, confirmation : ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if n1 != n2 {
		fmt.Fprintln(os.Stderr, "Les deux saisies diffèrent.")
		return 1
	}
	fmt.Println("Vérification et chiffrement (Argon2id, quelques secondes)…")
	var st approveResp
	err = json.NewEncoder(conn).Encode(approveReq{Action: "passwd", Name: name, Passphrase: cur, New: n1})
	cur, n1, n2 = "", "", ""
	if err != nil || json.NewDecoder(conn).Decode(&st) != nil {
		fmt.Fprintln(os.Stderr, "dialogue impossible avec Rempart")
		return 1
	}
	if st.Error != "" {
		fmt.Fprintln(os.Stderr, "Refusé :", st.Error)
		return 1
	}
	fmt.Println("Phrase changée. Elle n'est connue que de vous.")
	return 0
}
