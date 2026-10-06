#!/bin/sh
# entrypoint.sh - initialise le token SoftHSM au premier démarrage (démonstration), puis lance Rempart.
# Entrées : PIN et PIN SO lus dans le volume de secrets (/run/secrets, créés par « rempart setup-secrets -softhsm »).
# Contexte : image softhsm uniquement. Les PIN ne passent jamais par argv : softhsm2-util les lit au terminal.
set -eu
PIN_FILE="${REMPART_PKCS11_PIN_FILE:-/run/secrets/hsm_pin}"
SO_PIN_FILE="${REMPART_PKCS11_SO_PIN_FILE:-/run/secrets/hsm_so_pin}"
LABEL="${REMPART_TOKEN_LABEL:-rempart}"
if ! softhsm2-util --show-slots 2>/dev/null | grep -q "Label:.*${LABEL}"; then
  echo "Initialisation du token SoftHSM « ${LABEL} »"
  PIN="$(cat "$PIN_FILE")"
  SO_PIN="$(cat "$SO_PIN_FILE")"
  # softhsm2-util refuse une entrée qui n'est pas un terminal : « script » lui en
  # fournit un. printf est une commande interne (rien dans ps) et la sortie est
  # jetée, car le pseudo-terminal renvoie l'écho des PIN avant de le couper.
  if ! printf '%s\n%s\n%s\n%s\n' "$SO_PIN" "$SO_PIN" "$PIN" "$PIN" \
      | script -qec "softhsm2-util --init-token --free --label '${LABEL}'" /dev/null >/dev/null 2>&1; then
    PIN=""; SO_PIN=""
    echo "échec de l'initialisation du token SoftHSM" >&2
    exit 1
  fi
  PIN=""; SO_PIN=""
fi
exec /usr/local/bin/rempart -config /etc/rempart/rempart.yaml
