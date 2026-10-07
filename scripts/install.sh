#!/bin/sh
# install.sh - installe ou met à jour Rempart avec Docker ou Podman (compose, ou unité Quadlet pour Podman sous Linux).
# Entrées : options ci-dessous, saisies au terminal ; sorties : image, volume de secrets, .env (interface), conteneur démarré.
# Contexte : les secrets sont créés DANS le volume par « rempart setup-secrets » (conteneur jetable, sans réseau) : rien sur l'hôte, rien en argument.
set -eu
cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
Usage : scripts/install.sh [options]
  --engine docker|podman  moteur de conteneurs (défaut : podman s'il est installé, sinon docker)
  --softhsm               démonstration du mode HSM avec SoftHSM2 (docker-compose.hsm.yml)
  --quadlet               Podman sous Linux : unité systemd (deploy/podman/rempart.container) au lieu de compose
  --hsm-pin               ajouter au volume de secrets le PIN d'un HSM réel (passage au HSM depuis l'interface)
  --no-build              utiliser l'image déjà présente (chargée par « load » ou tirée d'un registre interne)
  --web-port N            port de l'interface sur la machine (défaut 8080 ; 8443 par exemple)
  --web-lan               interface ouverte sur le réseau local (défaut : cette machine seulement)
  --web-local             revenir à une interface accessible depuis cette machine seulement
Les choix --web-* sont gardés dans .env (sans secret) pour les relances suivantes.
Pour l'interface sur le port 443, à côté de DoH : Réglages → Chiffrement, une fois Rempart installé.
Relancer le script est sans risque : les secrets déjà présents sont gardés, l'image est reconstruite.
EOF
}

ENGINE=""; SOFTHSM=0; QUADLET=0; HSMPIN=0; BUILD=1
# Interface : choix précédents (.env), sinon locale sur 8080.
WEB_PORT=8080; WEB_BIND=127.0.0.1
if [ -f .env ]; then
  v=$(sed -n 's/^REMPART_WEB_PORT=//p' .env); [ -n "$v" ] && WEB_PORT=$v
  v=$(sed -n 's/^REMPART_WEB_BIND=//p' .env); [ -n "$v" ] && WEB_BIND=$v
fi
while [ $# -gt 0 ]; do
  case "$1" in
    --engine) ENGINE="${2:-}"; shift 2 ;;
    --softhsm) SOFTHSM=1; shift ;;
    --quadlet) QUADLET=1; shift ;;
    --hsm-pin) HSMPIN=1; shift ;;
    --no-build) BUILD=0; shift ;;
    --web-port) WEB_PORT="${2:-}"; shift 2 ;;
    --web-lan) WEB_BIND=0.0.0.0; shift ;;
    --web-local) WEB_BIND=127.0.0.1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "option inconnue : $1" >&2; usage >&2; exit 2 ;;
  esac
done

die() { echo "ERREUR : $*" >&2; exit 1; }
say() { printf '\n== %s\n' "$*"; }

case "$WEB_PORT" in ''|*[!0-9]*) die "--web-port : numéro de port attendu" ;; esac
[ "$WEB_PORT" -ge 1 ] && [ "$WEB_PORT" -le 65535 ] || die "--web-port : entre 1 et 65535"
case " 53 853 443 80 " in *" $WEB_PORT "*) die "--web-port $WEB_PORT : déjà utilisé par le DNS. Pour l'interface sur 443, activez « Interface aussi sur le port DoH » (Réglages → Chiffrement)" ;; esac

[ -t 0 ] && [ -t 1 ] || die "lancez ce script dans un terminal : il demande le mot de passe administrateur"

# ---- moteur ----
if [ -z "$ENGINE" ] && [ "$QUADLET" = 1 ]; then
  command -v podman >/dev/null 2>&1 || die "--quadlet suppose Podman, qui n'est pas installé (apt install podman ; Quadlet exige Podman 4.4 ou plus, Debian 13 ou plus récent)"
  ENGINE=podman
fi
if [ -z "$ENGINE" ]; then
  if command -v podman >/dev/null 2>&1; then ENGINE=podman
  elif command -v docker >/dev/null 2>&1; then ENGINE=docker
  else die "ni podman ni docker n'est installé"; fi
fi
case "$ENGINE" in docker|podman) ;; *) die "--engine docker ou podman" ;; esac
command -v "$ENGINE" >/dev/null 2>&1 || die "$ENGINE introuvable"
"$ENGINE" info >/dev/null 2>&1 || die "$ENGINE ne répond pas (service arrêté, ou machine Podman à démarrer : podman machine start)"
[ "$QUADLET" = 1 ] && [ "$ENGINE" != podman ] && die "--quadlet suppose Podman (--engine podman)"
[ "$QUADLET" = 1 ] && [ "$(uname -s)" != Linux ] && die "--quadlet suppose Linux et systemd"
[ "$QUADLET" = 1 ] && [ "$SOFTHSM" = 1 ] && die "--quadlet et --softhsm ne se combinent pas : la démonstration SoftHSM passe par compose"

if [ "$SOFTHSM" = 1 ]; then
  FILE=docker-compose.hsm.yml; PROJECT=rempart-hsm; IMAGE=rempart:softhsm; TARGET=softhsm
  SECVOL=rempart-hsm-secrets; CONTAINER=rempart-hsm; SETUP="-softhsm"
else
  FILE=docker-compose.yml; PROJECT=rempart; IMAGE=rempart:latest; TARGET=prod
  SECVOL=rempart-secrets; CONTAINER=rempart; SETUP=""
fi
[ "$HSMPIN" = 1 ] && SETUP="$SETUP -hsm-pin"
if [ "$QUADLET" = 1 ]; then DATAVOL=rempart-data; else DATAVOL="${PROJECT}_rempart-data"; fi

# ---- compose ----
COMPOSE=""
if [ "$QUADLET" = 0 ]; then
  if "$ENGINE" compose version >/dev/null 2>&1; then COMPOSE="$ENGINE compose"
  elif [ "$ENGINE" = docker ] && command -v docker-compose >/dev/null 2>&1; then COMPOSE="docker-compose"
  elif [ "$ENGINE" = podman ] && command -v podman-compose >/dev/null 2>&1; then COMPOSE="podman-compose"
  else die "aucun outil compose trouvé pour $ENGINE (docker compose, podman-compose)"; fi
fi

# ---- ports ----
# Ports standard, fixes : DNS 53, DoT/DoQ 853, DoH 443, HTTP 80 (ACME) ; interface au choix (8080 par défaut).
PORTS="53 853 443 80 $WEB_PORT"
port_busy() {
  if command -v ss >/dev/null 2>&1; then
    [ -n "$(ss -Hlntu "sport = :$1" 2>/dev/null)" ]
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1 || lsof -nP -iUDP:"$1" >/dev/null 2>&1
  else
    return 1
  fi
}
# Une version de Rempart déjà lancée occupe ses propres ports : on l'arrête avant de vérifier.
if [ "$QUADLET" = 1 ]; then
  if [ "$(id -u)" = 0 ]; then systemctl stop rempart 2>/dev/null || true; else systemctl --user stop rempart 2>/dev/null || true; fi
else
  "$ENGINE" rm -f "$CONTAINER" >/dev/null 2>&1 || true
fi
busy=""
for p in $PORTS; do port_busy "$p" && busy="$busy $p"; done
if [ -n "$busy" ]; then
  echo "Ports déjà utilisés sur cette machine :$busy" >&2
  command -v ss >/dev/null 2>&1 && for p in $busy; do ss -Hlntup "sport = :$p" 2>/dev/null >&2; done
  case " $busy " in *" 53 "*) echo "Port 53 : souvent systemd-resolved ; DNSStubListener=no dans /etc/systemd/resolved.conf le libère." >&2 ;; esac
  die "libérez ces ports puis relancez le script"
fi
if [ "$ENGINE" = podman ] && [ "$(uname -s)" = Linux ] && [ "$(podman info --format '{{.Host.Security.Rootless}}')" = true ]; then
  start=$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || echo 1024)
  [ "$start" -le 53 ] || die "Podman sans root ne peut pas ouvrir les ports sous $start : sudo sysctl -w net.ipv4.ip_unprivileged_port_start=53 (et dans /etc/sysctl.d/ pour le garder)"
fi

# ---- image ----
if [ "$BUILD" = 1 ]; then
  say "Construction de l'image $IMAGE"
  "$ENGINE" build --target "$TARGET" -t "$IMAGE" .
else
  "$ENGINE" image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE absente (--no-build)"
fi

# ---- secrets ----
say "Secrets (volume $SECVOL)"
"$ENGINE" volume inspect "$SECVOL" >/dev/null 2>&1 || "$ENGINE" volume create "$SECVOL" >/dev/null
DATAMOUNT=""
if "$ENGINE" volume inspect "$DATAVOL" >/dev/null 2>&1; then DATAMOUNT="-v $DATAVOL:/var/lib/rempart:ro"; fi
setup() { # conteneur jetable, sans réseau, qui seul écrit dans le volume de secrets
  # shellcheck disable=SC2086 # DATAMOUNT et les options sont des listes voulues
  "$ENGINE" run --rm --network none -v "$SECVOL:/run/secrets" $DATAMOUNT \
    --entrypoint /usr/local/bin/rempart "$@"
}
# Reprise d'une installation faite avec l'ancien dossier secrets/ : la phrase
# du keystore est passée par l'entrée standard, jamais en argument.
if [ "$SOFTHSM" = 0 ] && [ -n "$DATAMOUNT" ] && [ -s secrets/keystore_passphrase.txt ]; then
  setup -i "$IMAGE" setup-secrets -import keystore_passphrase < secrets/keystore_passphrase.txt
fi
# shellcheck disable=SC2086
setup -it "$IMAGE" setup-secrets -data /var/lib/rempart $SETUP

# ---- démarrage ----
say "Démarrage"
if [ "$QUADLET" = 1 ]; then
  if [ "$(id -u)" = 0 ]; then UNITDIR=/etc/containers/systemd; SC="systemctl"
  else UNITDIR="$HOME/.config/containers/systemd"; SC="systemctl --user"; fi
  mkdir -p "$UNITDIR"
  if [ "$WEB_BIND" = 0.0.0.0 ]; then PUB="$WEB_PORT:8080/tcp"; else PUB="$WEB_BIND:$WEB_PORT:8080/tcp"; fi
  sed "s|^PublishPort=127.0.0.1:8080:8080/tcp|PublishPort=$PUB|" deploy/podman/rempart.container > "$UNITDIR/rempart.container"
  $SC daemon-reload
  $SC restart rempart
else
  # Interface : adresse et port choisis, lus par compose dans .env.
  printf '# .env - interface de Rempart (scripts/install.sh --web-port, --web-lan) ; aucun secret.\nREMPART_WEB_BIND=%s\nREMPART_WEB_PORT=%s\n' "$WEB_BIND" "$WEB_PORT" > .env
  # Réglages propres à la machine (adresse d'écoute de l'interface…) : fichier
  # local non versionné, chargé après le fichier du dépôt.
  OVERRIDE=""; [ "$SOFTHSM" = 0 ] && [ -f docker-compose.override.yml ] && OVERRIDE="-f docker-compose.override.yml"
  # shellcheck disable=SC2086
  $COMPOSE -f "$FILE" $OVERRIDE up -d
fi

# ---- effacement du mot de passe initial ----
# Une fois l'état scellé créé, le mot de passe y est haché : le fichier ne sert plus.
DATAMOUNT="-v $DATAVOL:/var/lib/rempart:ro"
i=0; rc=3
while [ $i -lt 40 ]; do
  "$ENGINE" volume inspect "$DATAVOL" >/dev/null 2>&1 && {
    rc=0; setup "$IMAGE" setup-secrets -data /var/lib/rempart -forget-admin >/dev/null 2>&1 || rc=$?
    [ "$rc" = 3 ] || break
  }
  i=$((i + 1)); sleep 3
done
if [ "$rc" != 0 ]; then
  echo "Rempart n'a pas créé son état en 2 minutes : voir « $ENGINE logs $CONTAINER »." >&2
  echo "Le mot de passe initial reste dans le volume ; relancez ce script une fois le problème corrigé." >&2
  exit 1
fi
echo "Rempart est démarré ; le mot de passe initial a été effacé du volume (il est haché dans l'état scellé)."

if [ -d secrets ]; then
  printf "\nL'ancien dossier secrets/ contient des secrets en clair et ne sert plus. Le supprimer ? [o/N] "
  read -r rep
  case "$rep" in
    o|O|oui) for f in secrets/*; do [ -f "$f" ] && { shred -u "$f" 2>/dev/null || rm -f "$f"; }; done; rmdir secrets && echo "secrets/ supprimé." ;;
    *) echo "secrets/ conservé : supprimez-le vous-même une fois l'installation vérifiée." ;;
  esac
fi

if [ "$WEB_BIND" = 0.0.0.0 ]; then WEB_URL="https://<nom ou adresse du serveur>:$WEB_PORT"; else WEB_URL="https://localhost:$WEB_PORT (depuis cette machine, ou par un tunnel SSH)"; fi
cat <<EOF

Interface : $WEB_URL  (utilisateur admin)
Certificat auto-signé tant que vous n'en obtenez pas un (Sécurité → Certificat).
Journaux : $ENGINE logs $CONTAINER
EOF
