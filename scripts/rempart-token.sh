#!/bin/sh
# rempart-token.sh - crée un jeton d'API Rempart avec un compte administrateur
# (local ou LDAP), pour automatiser une installation (Ansible, cloud-init…).
#
#   ./scripts/rempart-token.sh -u https://rempart.maison.lan:8080 \
#       -n installation -s admin -d 30 -o /etc/rempart/api.auth --cacert ac.pem
#
# Le mot de passe est lu dans REMPART_PASSWORD_FILE (fichier 0600, par exemple
# un secret Ansible déchiffré), sinon demandé au terminal sans écho ; jamais en
# argument. Il passe à curl par
# l'entrée standard (invisible dans ps). Code TOTP : REMPART_OTP, ou demandé
# au terminal si le compte en a un. Le fichier écrit (-o) contient l'en-tête
# « Authorization: Bearer rmp_… » en 0600, prêt pour curl -H @fichier.
# Sans -o, le jeton est écrit sur la sortie standard.
set -eu

URL="${REMPART_URL:-https://localhost:8080}"
USER_NAME="${REMPART_USER:-admin}"
PW_FILE="${REMPART_PASSWORD_FILE:-}"
NAME="installation"; SCOPES="admin"; DAYS=30; OUT=""; CACERT=""

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; echo "Options : -u URL  -U utilisateur  -n nom  -s portées (read,tls,dnssec,admin,metrics,backup,sync)  -d jours (0 = sans expiration)  -o fichier  --cacert ac.pem"; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    -u) URL="$2"; shift 2 ;;
    -U) USER_NAME="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    -s) SCOPES="$2"; shift 2 ;;
    -d) DAYS="$2"; shift 2 ;;
    -o) OUT="$2"; shift 2 ;;
    --cacert) CACERT="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "option inconnue : $1" >&2; usage ;;
  esac
done
case "$DAYS" in ''|*[!0-9]*) echo "-d : nombre de jours attendu" >&2; exit 2 ;; esac
if [ -n "$PW_FILE" ]; then
  [ -r "$PW_FILE" ] || { echo "mot de passe introuvable : $PW_FILE (REMPART_PASSWORD_FILE)" >&2; exit 2; }
elif [ ! -t 0 ]; then
  echo "pas de terminal : fournissez le mot de passe par REMPART_PASSWORD_FILE" >&2; exit 2
fi
command -v curl >/dev/null || { echo "curl est requis" >&2; exit 2; }

# Échappement JSON minimal (barre oblique inverse, guillemet, retours ligne retirés).
jstr() { printf '%s' "$1" | tr -d '\r\n' | sed 's/\\/\\\\/g; s/"/\\"/g'; }
field() { sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p"; }

JAR="$(mktemp)"; trap 'curl -sS $TLS -b "$JAR" -H "X-Rempart: 1" -X POST "$URL/api/logout" >/dev/null 2>&1 || true; rm -f "$JAR"' EXIT
TLS=""; [ -n "$CACERT" ] && TLS="--cacert $CACERT"
call() { # call <chemin> : corps JSON lu sur l'entrée standard
  curl -sS $TLS -b "$JAR" -c "$JAR" -H 'X-Rempart: 1' -H 'Content-Type: application/json' --data @- -w '\n%{http_code}' "$URL$1"
}

if [ -n "$PW_FILE" ]; then
  PW="$(cat "$PW_FILE")"
else
  printf 'Mot de passe de %s : ' "$USER_NAME" >&2
  stty -echo; trap 'stty echo' INT; read -r PW; stty echo; echo >&2
fi
RESP="$(printf '{"username":"%s","password":"%s"}' "$(jstr "$USER_NAME")" "$(jstr "$PW")" | call /api/login)"
PW=""
CODE="$(printf '%s' "$RESP" | tail -n1)"; BODY="$(printf '%s' "$RESP" | sed '$d')"
[ "$CODE" = 200 ] || { echo "connexion refusée ($CODE) : $BODY" >&2; exit 1; }

if printf '%s' "$BODY" | grep -q '"second_factor": *true'; then
  CH="$(printf '%s' "$BODY" | field challenge)"
  OTP="${REMPART_OTP:-}"
  if [ -z "$OTP" ]; then
    [ -t 0 ] || { echo "second facteur requis : définissez REMPART_OTP" >&2; exit 1; }
    printf 'Code de double authentification : ' >&2; read -r OTP
  fi
  RESP="$(printf '{"challenge":"%s","code":"%s"}' "$(jstr "$CH")" "$(jstr "$OTP")" | call /api/login/otp)"
  CODE="$(printf '%s' "$RESP" | tail -n1)"
  [ "$CODE" = 200 ] || { echo "code refusé ($CODE) : $(printf '%s' "$RESP" | sed '$d')" >&2; exit 1; }
fi

SC="$(printf '%s' "$SCOPES" | sed 's/[[:space:]]//g; s/,/","/g')"
RESP="$(printf '{"name":"%s","scopes":["%s"],"days":%s}' "$(jstr "$NAME")" "$SC" "$DAYS" | call /api/tokens)"
CODE="$(printf '%s' "$RESP" | tail -n1)"; BODY="$(printf '%s' "$RESP" | sed '$d')"
[ "$CODE" = 200 ] || { echo "création refusée ($CODE) : $BODY" >&2; exit 1; }
TOKEN="$(printf '%s' "$BODY" | field token)"
case "$TOKEN" in rmp_*) ;; *) echo "réponse inattendue : $BODY" >&2; exit 1 ;; esac

if [ -n "$OUT" ]; then
  umask 077
  printf 'Authorization: Bearer %s\n' "$TOKEN" > "$OUT"
  chmod 600 "$OUT"
  echo "jeton « $NAME » ($SCOPES) écrit dans $OUT" >&2
else
  printf '%s\n' "$TOKEN"
fi
