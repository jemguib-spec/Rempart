<#
.SYNOPSIS
  Crée un jeton d'API Rempart avec un compte administrateur (local ou LDAP),
  pour automatiser une installation.

.EXAMPLE
  powershell -File scripts/rempart-token.ps1 -Url https://rempart.maison.lan:8080 `
      -Name installation -Scopes admin -Days 30 -OutFile C:\rempart\api.auth

  Le mot de passe est lu dans -PasswordFile s'il est donné, sinon demandé au
  terminal sans écho ; jamais en argument. Code TOTP : -Otp ou $env:REMPART_OTP, sinon demandé.
  -OutFile écrit « Authorization: Bearer rmp_… » (droits limités à l'utilisateur),
  prêt pour curl.exe -H @fichier. Sans -OutFile, le jeton est écrit sur la sortie.
#>
param(
  [string]$Url = $(if ($env:REMPART_URL) { $env:REMPART_URL } else { "https://localhost:8080" }),
  [string]$User = $(if ($env:REMPART_USER) { $env:REMPART_USER } else { "admin" }),
  [string]$PasswordFile = $env:REMPART_PASSWORD_FILE,
  [string]$Name = "installation",
  [string[]]$Scopes = @("admin"),
  [ValidateRange(0, 730)][int]$Days = 30,
  [string]$Otp = $env:REMPART_OTP,
  [string]$OutFile
)
$ErrorActionPreference = "Stop"
$Url = $Url.TrimEnd("/")
if ($PasswordFile -and -not (Test-Path $PasswordFile)) { throw "mot de passe introuvable : $PasswordFile" }
$Scopes = @($Scopes | ForEach-Object { $_ -split "," } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

$common = @{ WebSession = $null; ContentType = "application/json"; Headers = @{ "X-Rempart" = "1" } }
# Pas d'option pour ignorer le certificat : avec le certificat auto-signé,
# importez-le (ou l'AC de votre PKI) dans le magasin « Autorités racines » de l'utilisateur.
function Invoke-Rempart([string]$Path, $Body, [ref]$Session) {
  $p = $common.Clone()
  $p.Remove("WebSession")
  if ($Session.Value) { $p.WebSession = $Session.Value } else { $p.SessionVariable = "s" }
  try {
    $r = Invoke-RestMethod -Method Post -Uri ($Url + $Path) -Body ($Body | ConvertTo-Json -Compress) @p
  } catch {
    $msg = $_.ErrorDetails.Message; if (-not $msg) { $msg = $_.Exception.Message }
    throw "$Path : $msg"
  }
  if (-not $Session.Value) { $Session.Value = $s }
  return $r
}

$session = $null
if ($PasswordFile) {
  $pw = (Get-Content -Raw $PasswordFile).TrimEnd("`r", "`n")
} else {
  $sec = Read-Host "Mot de passe de $User" -AsSecureString
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
  try { $pw = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
try {
  $r = Invoke-Rempart "/api/login" @{ username = $User; password = $pw } ([ref]$session)
  $pw = $null
  if ($r.second_factor) {
    if (-not $Otp) { $Otp = Read-Host "Code de double authentification" }
    $null = Invoke-Rempart "/api/login/otp" @{ challenge = $r.challenge; code = $Otp } ([ref]$session)
  }
  $t = Invoke-Rempart "/api/tokens" @{ name = $Name; scopes = $Scopes; days = $Days } ([ref]$session)
  if (-not ($t.token -like "rmp_*")) { throw "réponse inattendue" }
  if ($OutFile) {
    Set-Content -Path $OutFile -Value ("Authorization: Bearer " + $t.token) -NoNewline -Encoding ascii
    # Droits réservés à l'utilisateur courant.
    $acl = Get-Acl $OutFile; $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $null = $acl.RemoveAccessRule($_) }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule([Security.Principal.WindowsIdentity]::GetCurrent().Name, "FullControl", "Allow")))
    Set-Acl $OutFile $acl
    Write-Host "jeton « $Name » ($($Scopes -join ', ')) écrit dans $OutFile"
  } else {
    $t.token
  }
} finally {
  if ($session) { try { $null = Invoke-Rempart "/api/logout" @{} ([ref]$session) } catch {} }
}
