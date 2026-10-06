# Installer Rempart

Guide pas à pas. Le [README](README.md) décrit toutes les fonctions ; cette page ne couvre que l'installation, la mise à jour et le dépannage du démarrage.

## 1. Prérequis

| Système | Moteur de conteneurs | Outil compose |
|---|---|---|
| Windows 10/11 | Docker Desktop, ou Podman Desktop (machine Podman démarrée) | `docker compose` (inclus), ou `podman compose` avec `podman-compose` ou `docker-compose` |
| Linux | Docker Engine ou Podman 4.4+ | `docker compose`, `podman-compose` ; ou rien avec `--quadlet` (Podman + systemd) |
| macOS | Docker Desktop ou Podman | idem |

Il faut aussi `git`, et environ 1 Go d'espace disque pour construire l'image. La construction télécharge les images de base `golang:1.24-bookworm` et `distroless/cc-debian12`. Les dépendances Go sont incluses dans `vendor/` : rien d'autre n'est téléchargé.

Ports utilisés sur la machine :

| Port | Usage |
|---|---|
| 53 UDP et TCP | DNS |
| 853 TCP et UDP | DNS-over-TLS, DNS-over-QUIC |
| 443 TCP | DNS-over-HTTPS |
| 80 TCP | HTTP : défi ACME http-01, ouvert seulement pendant l'obtention d'un certificat |
| 127.0.0.1:8080 | interface d'administration, accessible depuis la machine elle-même |

Si l'un de ces ports est déjà pris, l'installeur s'arrête et nomme le programme qui l'occupe. Causes fréquentes du port 53 occupé :
- Linux : systemd-resolved. Mettez `DNSStubListener=no` dans `/etc/systemd/resolved.conf`, puis `systemctl restart systemd-resolved`.
- Windows : le partage de connexion Internet (service SharedAccess) ou le proxy DNS de Hyper-V/WSL.

## 2. Installer

```bash
git clone https://github.com/jemguib-spec/Rempart.git
cd Rempart
./scripts/install.sh                 # Linux, macOS
```

```powershell
git clone https://github.com/jemguib-spec/Rempart.git
cd Rempart
powershell -ExecutionPolicy Bypass -File scripts\install.ps1   # Windows
```

L'installeur fait, dans l'ordre :

1. Il choisit Podman s'il est installé, sinon Docker. Pour imposer un moteur : `--engine docker` sous Linux, `-Engine docker` sous Windows.
2. Il vérifie les ports. Avec Podman sans root, il contrôle aussi que `net.ipv4.ip_unprivileged_port_start` vaut 53 au plus.
3. Il construit l'image (`rempart:latest`).
4. Il crée le volume de secrets `rempart-secrets`, puis lance `rempart setup-secrets` dans un conteneur jetable, sans réseau :
   - **phrase du keystore** : appuyez sur Entrée pour en générer une (256 bits). Elle s'affiche **une seule fois** : rangez-la dans votre gestionnaire de mots de passe. Elle sert à vérifier ou restaurer une sauvegarde, et à réinstaller sur une autre machine ;
   - **mot de passe du compte `admin`** : 12 caractères au moins, saisi deux fois, sans écho.
5. Il démarre Rempart et attend qu'il ait créé son état chiffré, puis efface le mot de passe initial du volume : il est désormais haché dans l'état.

Ouvrez ensuite `https://localhost:8080` et connectez-vous en `admin`. Le navigateur prévient que le certificat est auto-signé ; c'est normal tant que vous n'en avez pas obtenu un dans Sécurité → Certificat (ACME ou CSR). Activez tout de suite la double authentification ou une clé d'accès (Réglages → Compte).

Dernière étape : pointez le DNS de votre box, ou de vos postes, vers l'adresse IP de la machine.

### Options

| Linux / macOS | Windows | Effet |
|---|---|---|
| `--engine docker\|podman` | `-Engine docker\|podman` | impose le moteur |
| `--quadlet` | — | Podman sous Linux : installe `deploy/podman/rempart.container` (systemd) au lieu de compose |
| `--softhsm` | `-SoftHSM` | démonstration du mode HSM avec SoftHSM2 (PIN générés dans le volume `rempart-hsm-secrets`) |
| `--hsm-pin` | `-HsmPin` | ajoute au volume le PIN d'un HSM réel, avant le passage au HSM depuis l'interface |
| `--no-build` | `-NoBuild` | utilise une image déjà présente (`podman load`, registre interne) |

## 3. Où sont les secrets

Aucun secret n'est écrit dans le dossier du projet, ni passé en argument, ni écrit dans les journaux. Ils vivent dans le volume `rempart-secrets`, monté en lecture seule sur `/run/secrets` :

| Fichier | Contenu | Conservé |
|---|---|---|
| `keystore_passphrase` | phrase qui ouvre le keystore logiciel | oui, lue à chaque démarrage |
| `admin_password` | mot de passe initial du compte `admin` | non, effacé après le premier démarrage |
| `hsm_pin`, `hsm_so_pin` | PIN du token (mode HSM) | oui |

Ce sont des fichiers 0400 de l'utilisateur du conteneur (65532), dans un dossier 0700. Le volume protège par les droits du système, pas par du chiffrement : root sur l'hôte, ou l'administrateur de Docker ou de Podman, peut les lire. Pour qu'aucune phrase ne soit stockée, utilisez le démarrage sous quorum ou un HSM (README, « Sans HSM : quorum M sur N »).

## 4. Mettre à jour

```bash
git pull
./scripts/install.sh          # ou scripts\install.ps1
```

L'image est reconstruite et le conteneur recréé. Les secrets et les données sont gardés, rien n'est redemandé.

## 5. Reprendre une installation faite avec l'ancien dossier `secrets/`

Lancez l'installeur dans le dossier qui contient encore `secrets/`. Il fait passer `secrets/keystore_passphrase.txt` au conteneur par l'entrée standard, démarre Rempart sur les données existantes, puis propose de supprimer `secrets/`. Supprimez aussi les copies éventuelles de ce dossier : sauvegardes, archives, corbeille.

## 6. Installer à la main, sans l'installeur

```bash
docker build -t rempart:latest .                    # ou podman build
docker volume create rempart-secrets
docker run --rm -it --network none -v rempart-secrets:/run/secrets \
  --entrypoint /usr/local/bin/rempart rempart:latest setup-secrets
docker compose up -d                                # ou podman compose up -d
# une fois Rempart démarré, effacer le mot de passe initial :
docker run --rm --network none -v rempart-secrets:/run/secrets -v rempart_rempart-data:/var/lib/rempart:ro \
  --entrypoint /usr/local/bin/rempart rempart:latest setup-secrets -data /var/lib/rempart -forget-admin
```

## 7. Dépannage

| Symptôme | Cause et remède |
|---|---|
| « Ports déjà utilisés » | voir la section 1 ; libérez le port, puis relancez |
| « ne répond pas » au début | Docker Desktop arrêté, ou `podman machine start` à faire |
| « Podman sans root ne peut pas ouvrir les ports » | `sudo sysctl -w net.ipv4.ip_unprivileged_port_start=53`, à rendre permanent dans `/etc/sysctl.d/` |
| « n'a pas créé son état en 2 minutes » | `docker logs rempart` (ou `podman logs rempart`) donne la cause ; le mot de passe initial reste dans le volume, relancez l'installeur une fois corrigé |
| Rempart ne répond plus après un redémarrage | en démarrage sous quorum, il attend les dépositaires : `podman exec -it rempart rempart unseal` |
| Phrase du keystore perdue | sans elle ni quorum de secours, le keystore et les données chiffrées sont irrécupérables : c'est voulu |

Pour tout désinstaller (**destructif** : données et secrets perdus) :

```bash
docker compose down
docker volume rm rempart_rempart-data rempart-secrets
```
