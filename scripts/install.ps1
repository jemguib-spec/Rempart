# install.ps1 - installe ou met à jour Rempart sous Windows avec Docker Desktop ou Podman (compose).
# Entrées : paramètres ci-dessous, saisies au terminal ; sorties : image, volume de secrets, conteneur démarré sur les ports standard.
# Contexte : les secrets sont créés DANS le volume par « rempart setup-secrets » (conteneur jetable, sans réseau) : rien sur le disque Windows, rien en argument.
#
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1 [-Engine docker|podman] [-SoftHSM] [-HsmPin] [-NoBuild]
param(
  [ValidateSet("", "docker", "podman")][string]$Engine = "",
  [switch]$SoftHSM,   # démonstration du mode HSM avec SoftHSM2 (docker-compose.hsm.yml)
  [switch]$HsmPin,    # ajouter au volume le PIN d'un HSM réel (passage au HSM depuis l'interface)
  [switch]$NoBuild    # utiliser l'image déjà présente (chargée par « load » ou tirée d'un registre interne)
)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Die([string]$m) { Write-Host "ERREUR : $m" -ForegroundColor Red; exit 1 }
function Say([string]$m) { Write-Host "`n== $m" -ForegroundColor Cyan }
# Les commandes natives ne lèvent pas d'exception : on contrôle leur code de sortie.
function Check([string]$what) { if ($LASTEXITCODE -ne 0) { Die "$what (code $LASTEXITCODE)" } }
# Windows PowerShell 5.1 transforme la sortie d'erreur d'une commande native
# redirigée en exception quand ErrorActionPreference vaut Stop : on l'assouplit le temps de l'appel.
function Quiet([scriptblock]$b) {
  $old = $ErrorActionPreference; $ErrorActionPreference = "Continue"
  try { & $b *> $null } finally { $ErrorActionPreference = $old }
}

# ---- moteur ----
if (-not $Engine) {
  if (Get-Command podman -ErrorAction SilentlyContinue) { $Engine = "podman" }
  elseif (Get-Command docker -ErrorAction SilentlyContinue) { $Engine = "docker" }
  else { Die "ni podman ni docker n'est installé" }
}
if (-not (Get-Command $Engine -ErrorAction SilentlyContinue)) { Die "$Engine introuvable" }
Quiet { & $Engine info }
if ($LASTEXITCODE -ne 0) { Die "$Engine ne répond pas (Docker Desktop arrêté, ou : podman machine start)" }

if ($SoftHSM) {
  $File = "docker-compose.hsm.yml"; $Project = "rempart-hsm"; $Image = "rempart:softhsm"; $Target = "softhsm"
  $SecVol = "rempart-hsm-secrets"; $Container = "rempart-hsm"; $Setup = @("-softhsm")
} else {
  $File = "docker-compose.yml"; $Project = "rempart"; $Image = "rempart:latest"; $Target = "prod"
  $SecVol = "rempart-secrets"; $Container = "rempart"; $Setup = @()
}
if ($HsmPin) { $Setup += "-hsm-pin" }
$DataVol = "${Project}_rempart-data"

# ---- compose ----
$Compose = $null
Quiet { & $Engine compose version }
if ($LASTEXITCODE -eq 0) { $Compose = @($Engine, "compose") }
elseif ($Engine -eq "docker" -and (Get-Command docker-compose -ErrorAction SilentlyContinue)) { $Compose = @("docker-compose") }
elseif ($Engine -eq "podman" -and (Get-Command podman-compose -ErrorAction SilentlyContinue)) { $Compose = @("podman-compose") }
else { Die "aucun outil compose trouvé pour $Engine (docker compose, podman-compose)" }

# ---- ports ----
# Ports standard, fixes : DNS 53, DoT/DoQ 853, DoH 443, HTTP 80 (ACME), interface 8080 (locale).
Quiet { & $Engine rm -f $Container }   # une version déjà lancée occupe ses propres ports
$busy = @()
foreach ($p in 53, 853, 443, 80, 8080) {
  $tcp = Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue
  $udp = Get-NetUDPEndpoint -LocalPort $p -ErrorAction SilentlyContinue
  foreach ($e in @($tcp) + @($udp)) {
    if ($e) {
      $proc = (Get-Process -Id $e.OwningProcess -ErrorAction SilentlyContinue).ProcessName
      $busy += "  port $p : $proc (PID $($e.OwningProcess))"
    }
  }
}
if ($busy.Count -gt 0) {
  Write-Host "Ports déjà utilisés sur ce poste :" -ForegroundColor Yellow
  $busy | Sort-Object -Unique | ForEach-Object { Write-Host $_ }
  Write-Host "Port 53 : souvent le partage de connexion Internet (service SharedAccess) ou le proxy DNS de Hyper-V/WSL."
  Die "libérez ces ports puis relancez le script"
}

# ---- image ----
if (-not $NoBuild) {
  Say "Construction de l'image $Image"
  & $Engine build --target $Target -t $Image .
  Check "construction de l'image"
} else {
  Quiet { & $Engine image inspect $Image }
  if ($LASTEXITCODE -ne 0) { Die "image $Image absente (-NoBuild)" }
}

# ---- secrets ----
Say "Secrets (volume $SecVol)"
Quiet { & $Engine volume inspect $SecVol }
if ($LASTEXITCODE -ne 0) { & $Engine volume create $SecVol | Out-Null; Check "création du volume $SecVol" }
function Get-DataMount {
  Quiet { & $Engine volume inspect $DataVol }
  if ($LASTEXITCODE -eq 0) { return @("-v", "${DataVol}:/var/lib/rempart:ro") }
  return @()
}
# Conteneur jetable, sans réseau, qui seul écrit dans le volume de secrets.
$base = @("run", "--rm", "--network", "none", "-v", "${SecVol}:/run/secrets") + (Get-DataMount) + @("--entrypoint", "/usr/local/bin/rempart")

# Reprise d'une installation faite avec l'ancien dossier secrets\ : la phrase du
# keystore passe par l'entrée standard du conteneur, jamais en argument.
$old = "secrets\keystore_passphrase.txt"
if (-not $SoftHSM -and (Get-DataMount).Count -gt 0 -and (Test-Path $old) -and (Get-Item $old).Length -gt 0) {
  Get-Content -Raw $old | & $Engine @base -i $Image setup-secrets -import keystore_passphrase
  Check "reprise de la phrase du keystore"
}
& $Engine @base -it $Image setup-secrets -data /var/lib/rempart @Setup
Check "création des secrets"

# ---- démarrage ----
Say "Démarrage"
$cexe = $Compose[0]; $cargs = @($Compose | Select-Object -Skip 1) + @("-f", $File, "up", "-d")
& $cexe @cargs
Check "démarrage par compose"

# ---- effacement du mot de passe initial ----
# Une fois l'état scellé créé, le mot de passe y est haché : le fichier ne sert plus.
$rc = 3
for ($i = 0; $i -lt 40 -and $rc -eq 3; $i++) {
  $dm = Get-DataMount
  if ($dm.Count -gt 0) {
    $fargs = @("run", "--rm", "--network", "none", "-v", "${SecVol}:/run/secrets") + $dm + @("--entrypoint", "/usr/local/bin/rempart", $Image, "setup-secrets", "-data", "/var/lib/rempart", "-forget-admin")
    Quiet { & $Engine @fargs }
    $rc = $LASTEXITCODE
  }
  if ($rc -eq 3) { Start-Sleep -Seconds 3 }
}
if ($rc -ne 0) {
  Write-Host "Rempart n'a pas créé son état en 2 minutes : voir « $Engine logs $Container »." -ForegroundColor Yellow
  Die "le mot de passe initial reste dans le volume ; relancez ce script une fois le problème corrigé"
}
Write-Host "Rempart est démarré ; le mot de passe initial a été effacé du volume (il est haché dans l'état scellé)."

if (Test-Path secrets) {
  $rep = Read-Host "`nL'ancien dossier secrets\ contient des secrets en clair et ne sert plus. Le supprimer ? [o/N]"
  if ($rep -match '^(o|oui)$') {
    Remove-Item -Recurse -Force secrets
    Write-Host "secrets\ supprimé. Pensez aux copies : sauvegardes, archives, corbeille."
  } else {
    Write-Host "secrets\ conservé : supprimez-le vous-même une fois l'installation vérifiée."
  }
}

Write-Host @"

Interface : https://localhost:8080  (utilisateur admin)
Certificat auto-signé tant que vous n'en obtenez pas un (Sécurité → Certificat).
Journaux : $Engine logs $Container
"@
