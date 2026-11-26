# container-to-service.awk - traduit l'unité Quadlet rempart.container en unité systemd classique (podman run), pour Podman < 4.4 qui n'a pas Quadlet (Debian 12).
# Entrées : le fichier .container sur l'entrée standard ; variable podman (chemin absolu du binaire). Sortie : rempart.service.
# Contexte : appelé par scripts/install.sh --quadlet. Même modèle que « podman generate systemd --new » (Type=notify, fichier cidfile).
# Toute clé [Container] inconnue arrête la traduction : mieux vaut échouer que lancer un conteneur sans une option de durcissement.

function fail(msg) { print "container-to-service : " msg > "/dev/stderr"; bad = 1; exit 1 }
function arg(a) { run = run " " a }
function quoted(a) { if (a ~ /[ \t"\\]/) { gsub(/\\/, "\\\\", a); gsub(/"/, "\\\"", a); return "\"" a "\"" } return a }

/^[ \t]*(#|;|$)/ { next }
/^\[.*\]$/ { sec = substr($0, 2, length($0) - 2); next }
{
  eq = index($0, "=")
  if (eq == 0) fail("ligne inattendue : " $0)
  k = substr($0, 1, eq - 1); v = substr($0, eq + 1)
}
sec == "Unit" { unit = unit $0 "\n"; next }
sec == "Install" { install = install $0 "\n"; next }
sec == "Service" {
  if (k == "ExecStartPre") pre = pre $0 "\n"; else service = service $0 "\n"
  next
}
sec == "Container" {
  if (k == "Image") image = v
  else if (k == "ContainerName") arg("--name " v)
  else if (k == "PublishPort") arg("-p " v)
  else if (k == "Volume") arg("-v " v)
  else if (k == "Environment") arg("-e " quoted(v))
  else if (k == "Network") arg("--network " v)
  else if (k == "ReadOnly") { if (v == "true") arg("--read-only") }
  else if (k == "NoNewPrivileges") { if (v == "true") arg("--security-opt=no-new-privileges") }
  else if (k == "DropCapability") arg("--cap-drop=" v)
  else if (k == "Sysctl") arg("--sysctl=" v)
  else if (k == "Tmpfs") arg("--tmpfs=" v)
  else if (k == "Ulimit") arg("--ulimit=" v)
  else if (k == "HealthCmd") arg(quoted("--health-cmd=" v))
  else if (k == "HealthInterval") arg("--health-interval=" v)
  else if (k == "PodmanArgs") arg(v)
  else fail("clé [Container] non traduite : " k)
  next
}
{ fail("section inattendue : [" sec "]") }

END {
  if (bad) exit 1
  if (image == "") fail("Image= manquante")
  print "# rempart.service - généré par scripts/install.sh --quadlet depuis deploy/podman/rempart.container (Podman sans Quadlet)."
  print "[Unit]"
  printf "%s", unit
  print ""
  print "[Service]"
  print "Environment=PODMAN_SYSTEMD_UNIT=%n"
  print "Type=notify"
  print "NotifyAccess=all"
  printf "%s", pre
  print "ExecStartPre=/bin/rm -f %t/%n.ctr-id"
  print "ExecStart=" podman " run --cidfile=%t/%n.ctr-id --cgroups=no-conmon --rm --sdnotify=conmon -d --replace" run " " image
  print "ExecStop=" podman " stop --ignore -t 10 --cidfile=%t/%n.ctr-id"
  print "ExecStopPost=" podman " rm -f --ignore -t 10 --cidfile=%t/%n.ctr-id"
  print "TimeoutStopSec=70"
  printf "%s", service
  print ""
  print "[Install]"
  printf "%s", install
}
