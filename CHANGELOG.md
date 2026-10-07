# Journal des versions

## 1.1.0 — 2026-10-06

### Accès mobile et interface

- **Zones locales : noms génériques** (`*`, RFC 4592). Réponse synthétisée au nom demandé, avec les signatures du joker et la preuve que le nom exact n'existe pas (NSEC, NSEC3), NODATA compris. Le validateur DNSSEC accepte désormais un NSEC dont le propriétaire est le joker lui-même : le label `*` n'est pas compté dans le champ Labels de sa signature (RFC 4034 §3.1.3), il le refusait à tort.
- **DoT depuis Internet avec le jeton d'appareil** (Réglages → Chiffrement, désactivé par défaut). Le jeton lu dans le nom TLS (`<jeton>.<nom>`) ouvre l'accès comme le jeton DoH, pour le DNS privé natif d'Android en 4G. Un jeton inconnu reste refusé, et les zones internes ne sont jamais servies hors du réseau. Le nom circule en clair : le risque (réutilisation du jeton par qui observe le trafic) est affiché à côté de l'interrupteur.
- **Interface sur le port DoH** (Réglages → Chiffrement, désactivé par défaut) : `https://<nom du serveur>/` sans port 8080 ni tunnel, pour les clients des réseaux autorisés seulement (404 depuis Internet). Les deux écoutes partagent le même gestionnaire, sessions comprises.
- **Port et ouverture de l'interface à l'installation** : `--web-port 8443`, `--web-lan`, `--web-local` (`-WebPort`, `-WebLan`, `-WebLocal` sous Windows), gardés dans `.env`. Compose lit `REMPART_WEB_BIND` et `REMPART_WEB_PORT` ; l'unité Quadlet est adaptée à la copie.
- Appareils : le bloc d'inventaire devient « Déclarer un appareil du réseau local (par adresse IP ou MAC) » et celui des profils « Créer un profil mobile » : les deux s'appelaient « Ajouter un appareil ».

### Installation et secrets

- **Installeur unique, Docker ou Podman** : `scripts/install.sh` (Linux, macOS ; `--quadlet` pour l'unité systemd) et `scripts/install.ps1` (Windows). Il détecte le moteur et l'outil compose, vérifie les ports et la limite des ports sans root de Podman, construit l'image, crée les secrets, démarre Rempart puis efface le mot de passe initial. Le relancer met à jour sans toucher aux secrets. `--no-build` reprend une image déjà chargée, `--softhsm` installe la démonstration HSM.
- **Plus de dossier `secrets/` dans le projet.** Les secrets sont dans le volume `rempart-secrets` (fichiers 0400 de l'utilisateur 65532, dossier 0700), monté en lecture seule. Ils sont écrits par la nouvelle sous-commande `rempart setup-secrets`, dans un conteneur jetable sans réseau :
  - mot de passe administrateur saisi au terminal, sans écho, et effacé du volume dès que l'état scellé est créé ;
  - phrase du keystore générée (256 bits, `crypto/rand`), affichée une seule fois puis effacée de l'écran, ou saisie pour reprendre une installation ;
  - PIN SoftHSM générés, ou PIN d'un HSM réel saisi (`-hsm-pin`).
  
  L'écriture est atomique et n'écrase jamais un secret existant. `scripts/init-secrets.*` et `scripts/podman-secrets.sh` sont supprimés. Une installation existante est reprise : la phrase de `secrets/keystore_passphrase.txt` est passée au conteneur par l'entrée standard, puis l'installeur propose de supprimer le dossier.
- **Ports standard** dans `docker-compose.yml` comme dans l'unité Quadlet : 53, 853, 443, et 80 désormais publié pour le défi ACME http-01. L'interface reste sur `127.0.0.1:8080`.
- Démonstration SoftHSM : les PIN passaient en argument de `softhsm2-util` (visibles dans `ps`). Ils sont maintenant saisis par un pseudo-terminal, sortie jetée. `docker-compose.hsm.yml` a son propre projet (`rempart-hsm`) : son volume de données n'est plus partagé avec l'installation logicielle, dont il ne pouvait pas ouvrir l'état.
- `rempart-token.sh` et `.ps1` demandent le mot de passe sans écho quand aucun fichier n'est donné. `-SkipCertificateCheck` est retiré de `rempart-token.ps1` : déclarez l'AC à la place.
- `make run` crée les secrets de développement au terminal dans `data/secrets/` : le Makefile ne contient plus de mot de passe.


### Ajouts

- **Tableau de bord complet**, en deux vues : « Essentiel » (particulier) et « Complet » (entreprise, ouverte d'office quand l'instance a des zones, des flux RPZ, une réplication ou une copie vers un SIEM). Activité sur 1 h (minute), 24 h (10 min) et 7 jours (heure) ; carte de chaleur jour × heure ; issue des requêtes ; motifs de blocage (liste, Ma liste, RPZ, services, plages horaires, protections) ; transports chiffrés ou non ; types de requêtes ; codes de réponse ; histogramme des temps de réponse ; activité par groupe d'appareils ; état du service (listes, certificat, audit, validation DNSSEC, zones, secondaires, RPZ, réplication, SIEM, DHCP) avec les points à vérifier.
- Ces compteurs ne portent ni domaine ni appareil et restent disponibles quand le journal est désactivé. L'activité par groupe et les domaines bloqués ne sont gardés qu'en mode « statistiques anonymes » ou « journal complet » ; passer en mode « aucun journal » les efface de la mémoire (les domaines bloqués restaient jusqu'ici). Étiquettes bornées (64 valeurs) contre un client qui inventerait des types.
- API : `GET /api/stats` renvoie aussi `last_hour`, `week`, `peak_minute`, `qtypes`, `rcodes`, `protocols`, `block_reasons`, `groups`, `latency`, `log_mode` et `health` ; les champs existants sont inchangés.
- **Aide** (`/aide.html`) et **console API** (`/api.html`), liées depuis le menu. La console décrit les 124 routes de l'API (paramètres, corps, portée, exemple de réponse) et les exécute depuis la page, avec la session ou un jeton porteur, en montrant la commande `curl` équivalente ; les suppressions demandent une confirmation. `openapi.json` (OpenAPI 3) est généré par `scripts/gen-openapi.mjs`. Le test `web/apispec_test.go` échoue si une route n'est pas documentée ou si sa portée diffère.
- `scripts/rempart-token.sh` et `rempart-token.ps1` : création d'un jeton d'API avec un compte administrateur (local ou LDAP, TOTP compris), pour automatiser une installation.
- **Appareils → Tous les appareils** : inventaire du réseau, réuni à partir des baux DHCP, de la table de voisinage de l'hôte, des membres des groupes et des profils mobiles (rien ne vient du journal des requêtes). Pour chaque appareil : nom et type donnés dans Rempart, adresses, présence sur le réseau, groupe appliqué et comment il est reconnu (IP, MAC, réseau, profil). Groupe changé d'un menu, rangement de plusieurs appareils à la fois, test d'un domaine pour l'appareil, réservation de son adresse DHCP en un clic, ajout d'un appareil que Rempart ne voit pas. Les adresses MAC privées (bit « administrée localement ») sont signalées.
- Éditeur de groupe : les appareils détectés s'ajoutent d'un clic ; les membres s'affichent par leur nom.
- DHCP : bouton « Réserver » sur chaque bail dynamique.
- API : `GET /api/inventory`, `PUT /api/inventory/name`, `POST /api/groups/assign`, `POST /api/dhcp/reserve`. Les noms d'appareils sont propres à chaque instance (non répliqués) ; chaque action est inscrite dans l'audit (`appareil.nom`, `appareil.groupe`, `dhcp.bail-réservé`).

- **Réglages → Chiffrement** : interrupteur DNS-over-HTTPS et DNS-over-TLS appliqué à chaud, sans redémarrage. Un port occupé est signalé dans l'interface sans arrêter Rempart et sans enregistrer le choix. Adresses et ports restent dans `doh.listen` et `dot.listen`. Propre à chaque instance (non répliqué), inscrit dans l'audit (`chiffrement.modifié`).
- Unité Quadlet : port 443 publié pour DoH.
- **Zones : assistant pour les non-spécialistes.** Les noms d'une zone s'affichent en liste lisible (nom complet, type en clair, valeur) avec Tester, Modifier et Supprimer. « Ajouter un nom » propose six cas : appareil (A/AAAA, avec les appareils connus du DHCP), alias, messagerie, texte, service (préréglages Minecraft, SIP, CalDAV, LDAP…) et saisie libre. Contrôle en direct, phrase d'aperçu, ligne écrite montrée, test de résolution après l'enregistrement. Le fichier de zone reste disponible en mode expert, avec « Vérifier sans enregistrer » ligne par ligne.
- **Création de zone guidée** : home.arpa recommandé, maison.lan, sous-domaine d'un domaine à soi ou nom libre ; avertissements pour `.local` (mDNS), un domaine public existant ou un nom sans point ; premiers appareils à cocher depuis les baux DHCP.
- API : `POST /api/zones/check` (vérification à blanc, une erreur par ligne) et `GET /api/zones/{zone}/lookup?q=&type=` (réponse de la zone chargée).

### Corrections

- Un appareil désigné exactement (IP, MAC, profil) dans deux groupes était rangé sans avertissement dans le dernier : enregistrer un groupe le retire désormais des autres, et l'interface le signale. Les réseaux (CIDR) peuvent toujours se recouvrir, le plus précis l'emporte.

- Premier démarrage : les zones signées de `defaults.zones` n'avaient pas leurs clés DNSSEC et n'étaient pas servies (« clé introuvable »).
- Une zone d'un seul label public (`fr`, `com`) est refusée : elle aurait rendu tout le domaine de premier niveau injoignable.
- Une zone qui recouvre le domaine des appareils du DHCP est refusée à la création (la règle n'existait que dans l'autre sens).
- Les erreurs de syntaxe des enregistrements sont expliquées en français (« adresse IPv4 invalide… »), message d'origine conservé.

### Ajouts (sécurité DNS)

- **Validateur DNSSEC local** : Rempart interroge ses résolveurs en amont avec DO et CD, puis reconstruit la chaîne de confiance depuis la racine (ancres KSK-2017 et KSK-2024, prêt pour la bascule de la racine du 11 octobre 2026). Il vérifie les signatures, les preuves NSEC et NSEC3 (opt-out compris), les jokers, les CNAME et DNAME. Une réponse falsifiée donne SERVFAIL avec l'erreur étendue « DNSSEC Bogus » (RFC 8914). Le bit AD n'est posé que sur une réponse validée localement, et seulement pour un client qui l'a demandé (RFC 6840). Les domaines transférés sont des ancres négatives. Réglages → Blocage → Protections ; `dnssec.trust_anchors` pour des zones internes signées. Métrique `rempart_dnssec_validations_total`.
- **NSEC3** (RFC 5155, paramètres RFC 9276) pour les zones locales : actif par défaut pour les nouvelles zones, interrupteur dans la politique de rotation. Les zones secondaires reçues en NSEC3 sont servies avec leurs preuves.
- **Rotation d'algorithme DNSSEC** (RFC 6781 §4.1.4, méthode prudente) : Zones → DNSSEC → « Changer d'algorithme ». À chaque étape, chaque RRset est signé dans chaque algorithme publié.
- **DNS-over-QUIC** (RFC 9250) : `doq.listen`, interrupteur à chaud dans Réglages → Chiffrement ; `quic-go` v0.59.1 vendorisé.
- **DNSCrypt v2** (XChaCha20-Poly1305 et XSalsa20-Poly1305) : `dnscrypt.listen`, clé de fournisseur Ed25519 dans le keystore (HSM compris), clés de résolveur renouvelées toutes les heures et jamais écrites sur disque, tampon `sdns://` dans l'interface. Vérifié avec dnscrypt-proxy.
- **RPZ** : déclencheurs `rpz-client-ip`, `rpz-nsdname` et `rpz-nsip`.
- **IXFR incrémental** (RFC 1995) : historique des versions en mémoire. Les signatures des RRsets inchangés sont reprises : une mise à jour ne re-signe que ce qui a changé.

### Ajouts (comptes, appareils, exploitation)

- **Clés d'accès WebAuthn (passkeys, FIDO2)** pour le compte local : second facteur, ou connexion sans mot de passe si la clé vérifie l'utilisateur. Réglages → Compte. `REMPART_RESET_OTP=1` les retire aussi.
- **Profils `.mobileconfig` signés** (CMS) par le certificat de l'interface ; la clé reste dans le keystore.
- **Réplication avec bascule et retour automatiques** : la réplique prend le rôle principal par intérim quand l'instance principale reste injoignable, les modifications faites pendant la panne sont conservées, puis l'instance préférée reprend la main. Une époque empêche deux instances principales.
- **Passage à un token HSM cloné** : Sécurité → Clés et HSM vérifie sans rien écrire que le token cible (clonage du constructeur) contient les mêmes clés, non extractibles, et que sa KEK ouvre les données actuelles, puis programme la bascule.

### Corrections

- Une réponse obtenue avec le bit CD (non validée) était mise en cache et servie aux autres clients.
- L'identifiant d'une liste reçu par réplication servait tel quel de nom de fichier : une instance principale compromise pouvait faire écrire hors du dossier des listes.
- La mémoire anti-rejeu des mises à jour dynamiques (RFC 2136) est désormais scellée sur disque avant le traitement : un redémarrage ne rouvre plus de fenêtre de rejeu.
- État scellé écrit avec `fsync` avant le renommage (un arrêt brutal pouvait laisser un fichier vide).
- DoH : l'écoute est fermée même quand l'arrêt suit immédiatement le démarrage (port resté occupé).
- `rempart.yaml` : valeurs négatives et `min_ttl` supérieur à `max_ttl` refusés.
- Métriques : durée négative ignorée par l'histogramme, horodatages écrits sans notation scientifique.

### Tests

- Nouveaux tests pour `sealed`, `secmem`, `tlsutil`, `state`, `config`, `cache`, `blocker`, `metrics`, et pour chaque fonction ci-dessus (DNSSEC validé contre des zones falsifiées, NSEC3 et rotation d'algorithme vérifiés RRset par RRset, WebAuthn avec un authentificateur Chromium virtuel, DNSCrypt avec dnscrypt-proxy, CMS avec OpenSSL, clone de token avec SoftHSM).

### Dépendances

- `golang.org/x/*` mis à jour (crypto v0.41.0, net v0.43.0, sys v0.35.0) pour `quic-go`. Les empreintes de `go.sum` ont été calculées hors de `sum.golang.org` : vérifiez-les une fois (`rm go.sum && go mod tidy && git diff go.sum`).

## 1.0.0 — 2026-10-06

Première version stable. Le format de l'état scellé et de la configuration YAML est désormais tenu compatible d'une version 1.x à l'autre ; les états de la 0.1 sont repris tels quels au démarrage.

### Ajouts

- **Appareils** : groupes (IP, CIDR, MAC, profil) avec leurs listes, règles, services bloqués en un clic, plages horaires, SafeSearch et YouTube restreint ; catégories parentales ; pause par groupe.
- **Profils mobiles** : jeton DoH par appareil (seul son SHA-256 est conservé), profil `.mobileconfig`, instructions Android et Windows.
- **DHCP** facultatif (RFC 2131), baux scellés, noms des appareils, second serveur DNS annoncé.
- **Haute disponibilité** : transferts de zone AXFR/IXFR avec NOTIFY, zones secondaires, réplication de la configuration entre instances ; TSIG (HMAC-SHA2) obligatoire.
- **Mises à jour dynamiques** RFC 2136 signées, avec anti-rejeu, séparées des enregistrements de l'administrateur.
- **RPZ** : flux de menaces par AXFR signé ou HTTPS, déclencheurs QNAME et adresse de réponse.
- **Supervision** : `/metrics` Prometheus, copie de l'audit signé vers un syslog ou un SIEM (RFC 5424, TLS RFC 5425).
- **Sauvegarde** : `GET /api/backup`, `rempart backup verify`, `rempart restore`, procédure documentée.
- Portées de jeton `metrics`, `backup` et `sync` (les deux dernières ne sont pas incluses dans `admin`).

### Changements

- Le numéro de série d'une zone avance à chaque modification et à chaque re-signature, même deux fois dans la même seconde.
- Le cache rejoue le démasquage CNAME et les déclencheurs RPZ d'adresse sur chaque réponse servie depuis le cache.
- Une requête signée TSIG reçoit une réponse signée ; une signature invalide, NOTAUTH.

### Sécurité (relecture indépendante avant publication)

- Transferts entrants, SOA et NOTIFY vérifiés avec la seule clé TSIG de la requête : une autre clé connue de Rempart (éditeur RPZ, client de mises à jour) ne peut plus signer la réponse destinée à un autre primaire.
- RFC 2136 : DNAME refusé ; NS et DS refusés au-dessus d'un nom de l'administrateur ; fudge limité à 300 s, anti-rejeu jusqu'à la fin de validité de la signature ; 10 000 enregistrements dynamiques par zone et 20 mises à jour par seconde au plus.
- RPZ : `$GENERATE` refusé, 2 millions d'enregistrements au plus, déclencheurs QNAME appliqués aux cibles CNAME, PASSTHRU limité aux flux suivants, DROP journalisé, redirections hors HTTPS refusées, clé d'accès de l'URL masquée.
- Réplication : aucune redirection suivie, listes `https://` seulement, clés locales jamais remplacées, réglages de confidentialité propres à chaque instance, au moins une réplique déclarée.
- Sauvegarde écrite dans un fichier temporaire puis envoyée ; journaux copiés jusqu'à leur taille d'ouverture (plus d'échec quand ils grandissent).
- Copies scellées des zones secondaires et des flux RPZ toutes rescellées à la rotation de la KEK, flux désactivés compris.
- Métriques : libellé `id` sur les listes et les flux (noms en double).

### Limites connues

Voir la section « Limites actuelles » du README (DoQ, DNSCrypt, IXFR incrémental, déclencheurs RPZ NSDNAME/NSIP).
