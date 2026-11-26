#!/bin/sh
# update.sh - met Rempart à jour depuis le dépôt git : récupère les nouveaux commits (avance rapide seulement) et reconstruit l'image si elle ne correspond plus au commit courant.
# Entrées : --engine, --target, --image, --restart ; sorties : dépôt avancé, image marquée du commit (label org.opencontainers.image.revision), journal sur la sortie standard (journalctl -u rempart).
# Contexte : lancé par le service systemd avant chaque démarrage (ExecStartPre, posé par « install.sh --auto-update »), ou à la main avec --restart pour construire pendant que l'ancienne version tourne encore.
# Ne touche jamais aux secrets ni aux données. Sans réseau, garde la version en place ; un échec n'empêche pas le service de démarrer (préfixe « - » dans l'unité).

usage() {
  cat <<'EOF'
Usage : scripts/update.sh [options]
  --engine docker|podman  moteur de conteneurs (défaut : podman s'il est installé, sinon docker)
  --target prod|softhsm   étape du Dockerfile (défaut : prod)
  --image NOM             image produite (défaut : rempart:latest)
  --restart               construire d'abord, puis redémarrer le service rempart : coupure du DNS réduite au redémarrage
Sans --restart, c'est ce que fait le service à chaque démarrage : systemctl restart rempart suffit.
EOF
}

main() {
  set -eu
  REPO=$(cd "$(dirname "$0")/.." && pwd)
  cd "$REPO"

  ENGINE=""; TARGET=prod; IMAGE=rempart:latest; RESTART=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --engine) ENGINE="${2:-}"; shift 2 ;;
      --target) TARGET="${2:-}"; shift 2 ;;
      --image) IMAGE="${2:-}"; shift 2 ;;
      --restart) RESTART=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) echo "option inconnue : $1" >&2; usage >&2; exit 2 ;;
    esac
  done
  if [ -z "$ENGINE" ]; then
    if command -v podman >/dev/null 2>&1; then ENGINE=podman; else ENGINE=docker; fi
  fi
  case "$ENGINE" in docker|podman) ;; *) echo "--engine docker ou podman" >&2; exit 2 ;; esac

  # Jamais d'invite d'identifiants : le service tourne sans terminal.
  GIT_TERMINAL_PROMPT=0; export GIT_TERMINAL_PROMPT
  LABEL=org.opencontainers.image.revision

  # Une seule mise à jour à la fois (service et lancement manuel).
  exec 9>"$REPO/.git/rempart-update.lock"
  if command -v flock >/dev/null 2>&1; then
    flock -w 3600 9 || { log "une autre mise à jour est en cours"; exit 1; }
  fi

  # ---- dépôt ----
  if g rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1; then
    # Rempart est souvent le DNS de la machine : arrêté, il ne résout plus
    # github.com. Le délai borne l'attente, et la version en place démarre.
    if timeout 90 git -c safe.directory="$REPO" fetch --quiet; then
      before=$(g rev-parse --short HEAD)
      if [ "$(g rev-parse HEAD)" = "$(g rev-parse '@{u}')" ]; then
        log "dépôt déjà à jour ($before)"
      elif g merge --ff-only --quiet '@{u}'; then
        log "dépôt mis à jour : $before → $(g rev-parse --short HEAD)"
      else
        log "avance rapide impossible (fichiers modifiés localement ou historique divergent) : version en place gardée"
      fi
    else
      log "dépôt injoignable (réseau ou DNS de la machine) : version en place gardée"
    fi
  else
    log "la branche $(g rev-parse --abbrev-ref HEAD) ne suit aucune branche distante : rien à récupérer"
  fi

  # ---- image ----
  head=$(g rev-parse HEAD); short=$(g rev-parse --short HEAD)
  current=$("$ENGINE" image inspect --format "{{ index .Config.Labels \"$LABEL\" }}" "$IMAGE" 2>/dev/null || true)
  if [ "$current" = "$head" ]; then
    log "image $IMAGE déjà construite pour $short"
  else
    log "construction de l'image $IMAGE pour $short"
    # Dépendances Go incluses (vendor/), images de base gardées en cache :
    # la construction n'a pas besoin du réseau après la première fois.
    "$ENGINE" build --target "$TARGET" --label "$LABEL=$head" -t "$IMAGE" .
    log "image $IMAGE construite"
  fi

  if [ "$RESTART" = 1 ]; then
    exec 9>&- # le démarrage relance ce script : il ne doit pas attendre ce verrou
    if [ "$(id -u)" = 0 ]; then set -- systemctl; else set -- systemctl --user; fi
    "$@" cat rempart >/dev/null 2>&1 || { log "aucun service rempart : lancez scripts/install.sh --auto-update"; exit 1; }
    log "redémarrage du service rempart"
    "$@" restart rempart
  fi

  # Anciennes images de Rempart, détachées de leur nom et plus utilisées.
  "$ENGINE" image prune -f --filter "label=$LABEL" >/dev/null 2>&1 || true
}

log() { printf 'rempart-update : %s\n' "$*"; }
g() { git -c safe.directory="$REPO" "$@"; }

# Tout le script est lu avant d'être exécuté : la mise à jour du dépôt peut
# remplacer ce fichier pendant qu'il tourne.
main "$@"
exit $?
