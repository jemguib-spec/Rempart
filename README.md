# Rempart DNS

Résolveur DNS filtrant (bloqueur de publicités et de traqueurs) conçu d'abord pour la sécurité et la confidentialité. Il sert aussi vos zones internes, signées en DNSSEC, avec des clés qui peuvent rester dans un HSM PKCS#11.

Une seule image de conteneur (Podman) ou un seul binaire Go. L'interface web est intégrée et ne dépend d'aucun CDN.

## Ce qui le distingue de Pi-hole et AdGuard Home

| | Rempart | Pi-hole / AdGuard Home |
|---|---|---|
| Langage du cœur | Go, sécurité mémoire | C (dnsmasq/FTL) / Go |
| Zones locales signées DNSSEC | ✅ KSK/ZSK, NSEC ou NSEC3, rotation d'algorithme, DS exporté | ❌ |
| Validation DNSSEC locale (depuis la racine) | ✅ réponses falsifiées refusées, AD posé par Rempart | Déléguée à l'amont |
| Clés dans un HSM (PKCS#11) | ✅ DNSSEC, TLS (DoT/DoH), audit, chiffrement | ❌ |
| Sans HSM : quorum M sur N, rotation des KEK | ✅ Shamir, démarrage verrouillé possible | ❌ |
| Historique des requêtes | Chiffré, une clé par jour, effacement cryptographique | En clair (SQLite) |
| IP des clients | Pseudonymisées (HMAC, clé changée chaque jour) | En clair |
| Journal des actions admin | Chaîné, signé, troncature détectée | ❌ |
| Double authentification | TOTP + codes de secours, passkeys WebAuthn (connexion sans mot de passe possible) | Non (Pi-hole : TOTP) |
| État et configuration sur disque | Scellés (AES-256-GCM, clé dans le keystore) | En clair |
| Démasquage des traqueurs CNAME, anti-rebinding | ✅ / ✅ | Partiel |
| Padding des requêtes chiffrées (RFC 8467) | ✅ | ❌ |
| Politique par groupe d'appareils, services, plages horaires, SafeSearch | ✅ | ✅ |
| Profils mobiles : jeton par appareil, haché, révocable | ✅ (SHA-256 seul conservé), profil Apple signé | AdGuard : identifiant client en clair |
| Serveur DHCP, baux | ✅ baux scellés | ✅ en clair |
| DNS-over-QUIC, DNSCrypt v2 | ✅ / ✅ (clé de fournisseur dans le HSM) | AdGuard Home : ✅ / ✅ |
| Transferts de zone AXFR/IXFR incrémental, NOTIFY, secondaires, TSIG | ✅ TSIG obligatoire, HMAC-SHA2 seulement | ❌ |
| Mises à jour dynamiques (RFC 2136) | ✅ TSIG + adresse, anti-rejeu persistant | ❌ |
| Flux de menaces RPZ | ✅ AXFR signé ou HTTPS, tous les déclencheurs | ❌ |
| Réplication entre instances | ✅ intégrée, bascule et retour automatiques | Outils tiers |
| Métriques Prometheus, audit vers syslog/SIEM | ✅ / ✅ (RFC 5424, TLS) | Exportateurs tiers / ❌ |
| Sauvegarde vérifiable et restauration | ✅ manifeste SHA-256, `backup verify` | Partielle |

## Installation (Docker ou Podman)

Le guide pas à pas (prérequis, ports, secrets, mise à jour, dépannage) est dans **[INSTALL.md](INSTALL.md)**. En bref :

```bash
./scripts/install.sh                                  # Linux, macOS
powershell -ExecutionPolicy Bypass -File scripts\install.ps1   # Windows (Docker Desktop ou Podman)
```

L'installeur choisit Podman s'il est présent, sinon Docker (`--engine docker|podman`, `-Engine` sous Windows), construit l'image, crée les secrets, démarre Rempart et vérifie qu'il a créé son état. On peut le relancer pour une mise à jour : les secrets existants sont gardés et l'image est reconstruite. Sur un serveur Linux avec Podman, `--quadlet` installe l'unité systemd (`deploy/podman/rempart.container`) au lieu de compose.

**Ports standard** : DNS 53 (UDP et TCP), DoT et DoQ 853, DoH 443, HTTP 80 (défi ACME http-01), interface sur `127.0.0.1:8080`. Si l'un d'eux est déjà pris, l'installeur s'arrête et indique le processus en cause (sous Linux, le port 53 est souvent tenu par systemd-resolved : `DNSStubListener=no` dans `/etc/systemd/resolved.conf`). Podman sans root exige `sysctl net.ipv4.ip_unprivileged_port_start=53` sur l'hôte ; l'installeur le vérifie.

**Secrets : aucun fichier dans le projet.** Ils vivent dans un volume dédié, `rempart-secrets`, monté en lecture seule sur `/run/secrets`. Ce sont des fichiers 0400 de l'utilisateur du conteneur (65532), dans un dossier 0700. Ils sont écrits par `rempart setup-secrets`, lancé dans un conteneur jetable sans réseau :

| Secret | Origine | Durée de vie |
|---|---|---|
| `keystore_passphrase` | générée (256 bits de `crypto/rand`, base64url), affichée une seule fois puis effacée de l'écran ; ou saisie, pour reprendre une installation existante | permanente : elle ouvre le keystore à chaque démarrage |
| `admin_password` | saisi au terminal, sans écho, deux fois | effacé du volume dès que Rempart a créé son état, où il est haché |
| `hsm_pin`, `hsm_so_pin` | générés (`--softhsm`) ou saisi (`--hsm-pin`, HSM réel) | permanents |

Rien ne transite par l'hôte, par la ligne de commande ni par les journaux. Rangez la phrase du keystore dans un gestionnaire de mots de passe : elle sert à vérifier ou restaurer une sauvegarde et à réinstaller sur une autre machine.

Limite : le volume protège les secrets par les droits du système, pas par du chiffrement. Root sur l'hôte, ou l'administrateur de Docker ou de Podman, les lit, comme les secrets Podman du pilote `file` par défaut ou ceux de Docker Compose hors Swarm. Contre celui qui détient le disque, seul le démarrage sous quorum (aucune phrase stockée) ou un HSM met la clé racine hors d'atteinte : voir [Sans HSM : quorum M sur N](#sans-hsm--quorum-m-sur-n-et-rotation-des-clés).

Une installation faite avec l'ancien dossier `secrets/` est reprise telle quelle : l'installeur passe `secrets/keystore_passphrase.txt` au conteneur par l'entrée standard, puis propose de supprimer le dossier.

Puis ouvrez `https://<serveur>:8080` (l'interface n'écoute que sur la machine elle-même : passez par un VPN ou un proxy inverse pour l'ouvrir ailleurs). Le certificat est auto-signé tant que vous n'en obtenez pas un depuis l'interface (ACME ou CSR). L'utilisateur est `admin`, avec le mot de passe choisi à l'installation. Pointez ensuite le DNS de votre box ou de vos postes vers l'adresse du serveur.

Sans l'installeur, l'ordre est le même : construire l'image, créer le volume, lancer `setup-secrets`, démarrer.

```bash
docker build -t rempart:latest .                     # ou podman
docker volume create rempart-secrets
docker run --rm -it --network none -v rempart-secrets:/run/secrets \
  --entrypoint /usr/local/bin/rempart rempart:latest setup-secrets
docker compose up -d                                 # ou podman compose, ou l'unité Quadlet
```

Pour obtenir l'empreinte d'un mot de passe : `rempart hash-password < fichier` (lu sur l'entrée standard, jamais en argument).

### Mode HSM

```bash
./scripts/install.sh --softhsm          # Windows : scripts\install.ps1 -SoftHSM
```

Cette variante utilise SoftHSM2 (un HSM logiciel) pour la démonstration. En production, avec un Thales Luna, un nShield, un YubiHSM 2 ou un Nitrokey, utilisez l'image `prod` et montez la bibliothèque PKCS#11 du constructeur. Indiquez ensuite son chemin dans `keystore.pkcs11.module` (voir les commentaires de `docker-compose.hsm.yml`).

Au premier démarrage, Rempart génère dans le token :

| Clé | Usage |
|---|---|
| `rempart-kek` (AES-256) | chiffre les clés de données : état, journal quotidien, tête d'audit |
| `rempart-tls` (ECDSA P-256) | handshake TLS de DoT, DoH et de l'interface |
| `rempart-audit` (ECDSA P-256) | signature du journal d'audit |
| `zone-<zone>-ksk` / `-zsk` | signature DNSSEC de chaque zone locale |

Toutes ces clés sont créées non exportables (`CKA_EXTRACTABLE=false`, `CKA_SENSITIVE=true`).

À la création d'une zone, le formulaire indique où ses clés seront générées (token, labels `zone-<zone>-ksk` et `-zsk`) et ne propose que les algorithmes dont le token annonce les mécanismes (`CKM_EC_KEY_PAIR_GEN` + `CKM_ECDSA`, `CKM_EC_EDWARDS_KEY_PAIR_GEN` + `CKM_EDDSA`). Si une bascule vers le HSM est programmée mais pas encore faite, il prévient que la clé serait importée : créez la zone après le redémarrage.

### Passer au HSM depuis l'interface

Sécurité → Clés et HSM propose un assistant en quatre étapes :

1. Choix de la bibliothèque PKCS#11, parmi celles trouvées dans `keystore.pkcs11.module_dirs`. Charger un module exécute son code : seuls les fichiers de ces dossiers, appartenant à root et non modifiables par d'autres, sont proposés, et `pkcs11-spy` est exclu.
2. Choix du token. L'état du PIN (déjà erroné, dernier essai, verrouillé) est affiché.
3. Test : connexion, présence des mécanismes, auto-test AES-GCM et ECDSA avec des objets de session. Rien n'est écrit dans le token. Au plus deux échecs de PIN par quart d'heure ; le dernier essai demande une confirmation explicite.
4. Programmation de la bascule, écrite dans `data_dir/keystore.json` (sans secret).

Au redémarrage suivant, avec le PIN fourni par `REMPART_PKCS11_PIN_FILE`, Rempart importe chaque clé dans le HSM comme objet non extractible et vérifie une signature avec la clé publique d'origine. Il rechiffre ensuite l'état, la tête d'audit et les clés du journal par la KEK du HSM, en sauvegardant les originaux. L'ancien keystore est mis de côté jusqu'à sa destruction depuis l'interface. Si la migration échoue avant toute modification, Rempart reste sur le keystore logiciel et affiche l'erreur ; si elle s'interrompt en cours de bascule, il refuse de démarrer sur l'ancien keystore et la reprend au démarrage suivant.

Les clés importées ont existé hors du HSM : l'interface les marque « importée ». Changez-les dès que possible (rotation DNSSEC, nouveau certificat) pour obtenir des clés générées dans le HSM.

### Passer à un autre HSM

Les clés de Rempart sont non extractibles : Rempart ne peut pas, et ne doit pas, les copier lui-même d'un HSM à l'autre. Clonez le token avec l'outil du constructeur (clonage de partition Luna, sauvegarde et restauration nShield, YubiHSM `wrap`…), puis Sécurité → Clés et HSM → « Passer à un autre HSM » :

1. Rempart ouvre le token cible en session de lecture seule (avec le même contexte PKCS#11 si c'est la même bibliothèque, pour ne pas couper le token en service) ;
2. il vérifie que chaque clé du token en service y existe avec la même clé publique, qu'elle signe correctement, qu'elle est non extractible et sensible ;
3. il vérifie que la KEK du token cible ouvre les données actuelles (clés de données de l'état scellé) ;
4. la bascule est programmée dans `keystore.json` ; au prochain démarrage, avec le PIN du nouveau token, Rempart l'utilise. Rien n'est rechiffré.

Au plus deux échecs de PIN par quart d'heure. Rien n'est jamais écrit dans le token cible.

## Zones locales : nommer ses appareils

Zones DNSSEC. Une zone est votre domaine privé (par exemple `home.arpa`) ; vous y donnez un nom à chaque appareil : `nas.home.arpa` plutôt que `192.168.1.10`. Ces noms ne servent qu'aux appareils qui utilisent Rempart comme serveur DNS.

- **Créer une zone** : trois étapes. Le nom (`home.arpa`, réservé à cet usage par la RFC 8375, est proposé d'abord ; l'interface prévient pour `.local`, qui gêne Bonjour/AirPrint, et pour un domaine public qui serait masqué), la signature DNSSEC, puis les premiers appareils à cocher parmi les baux DHCP.
- **Ajouter un nom** : un appareil, un alias, la messagerie, un texte, un service ou une ligne libre. Chaque champ est vérifié pendant la saisie ; une phrase résume l'effet (« nas.home.arpa donnera l'adresse 192.168.1.10 ») et la ligne de fichier de zone écrite est montrée. Après l'enregistrement, Rempart interroge la zone et affiche la réponse.
- **Mode expert** : le fichier de zone complet, avec « Vérifier sans enregistrer », qui indique la ligne fautive.
- **Noms génériques** : un nom `*` (ou `*.sous-domaine`) répond pour tous les noms qui n'existent pas en dessous (RFC 4592), avec les preuves DNSSEC (NSEC ou NSEC3) attendues par un validateur. Exemple : `* IN A 192.168.1.10` fait répondre `n-importe-quoi.home.arpa`.

## Inventaire des appareils

Appareils → Tous les appareils. Rempart réunit ce qu'il sait déjà de chaque appareil : baux de son DHCP, table de voisinage de l'hôte (`/proc/net/arp`, visible seulement si le conteneur partage le réseau de l'hôte), membres des groupes et profils mobiles. Rien ne vient du journal des requêtes : l'inventaire ne dit pas ce qu'un appareil consulte.

- Nom et type propres à Rempart (sans effet sur le DHCP), non répliqués.
- Groupe choisi dans un menu, ou pour plusieurs appareils à la fois ; l'appareil est désigné par sa MAC si elle est connue, sinon par son IP, et retiré des autres groupes.
- Test d'un domaine pour l'appareil, réservation de son adresse DHCP, ajout d'un appareil que Rempart ne voit pas.
- MAC privée signalée (« adresse Wi-Fi privée » d'iOS, Android, Windows) : si l'appareil change d'adresse, il quitte son groupe ; désactivez la rotation pour ce réseau ou utilisez un profil mobile.

Un appareil n'appartient qu'à un groupe : une adresse IP, une MAC ou un profil ajouté à un groupe est retiré des autres. Les réseaux (CIDR) peuvent se recouvrir, le plus précis l'emporte.

## Groupes d'appareils et contrôle parental

Appareils → Groupes. Un groupe réunit des appareils désignés par adresse IP, réseau CIDR, adresse MAC ou profil (`device:<id>`), et leur applique sa propre politique. Un appareil hors de tout groupe suit la politique générale (listes actives, Ma liste, Réglages). Ordre d'identification : profil, adresse exacte, adresse MAC, puis le réseau le plus précis. La MAC vient des baux DHCP de Rempart ou de la table de voisinage du noyau (`/proc/net/arp`), complète seulement si le conteneur partage le réseau de l'hôte.

| Élément | Effet |
|---|---|
| Listes | celles actives partout (option), plus des listes propres au groupe |
| Catégories | listes HaGeZi en un clic : adultes, jeux d'argent, réseaux sociaux, moteurs sans SafeSearch, contournement (DoH/VPN/proxy), menaces. Créées inactives dans la politique générale |
| Règles du groupe | blocages et exceptions ; une exception du groupe passe tout, plages horaires comprises |
| Services | 54 services en 8 familles (réseaux sociaux, vidéo, musique, messageries, jeux, IA, achats, rencontres) : une famille entière d'un clic, ou service par service ; recherche par nom ou domaine, domaines intégrés, sans téléchargement |
| Plages horaires | par jour et heure (une plage peut passer minuit) : services bloqués, ou coupure complète d'Internet |
| SafeSearch | Google, Bing, DuckDuckGo, Yandex, Pixabay : réponse CNAME vers l'adresse de filtrage de l'éditeur |
| YouTube | mode restreint modéré ou strict |

La pause d'un groupe, comme la pause générale, ne suspend que le filtrage publicitaire (listes, règles, services permanents) : les catégories, les plages horaires et SafeSearch restent actifs. Le cache est commun à tous les groupes ; le démasquage des CNAME est rejoué sur chaque réponse lue en cache, pour qu'une réponse obtenue par un appareil non filtré ne contourne rien pour les autres. Le fuseau des plages se règle dans Réglages → Général (Europe/Paris, par exemple ; les fuseaux sont intégrés au binaire). Appareils → Groupes permet aussi de tester un domaine pour un appareil donné, et le journal indique le groupe appliqué à chaque requête.

Limite du filtrage DNS : un appareil qui utilise son propre résolveur chiffré, un VPN ou un relais l'ignore. La catégorie « Contournement » bloque les plus connus ; elle ne remplace pas un pare-feu qui interdit le DNS sortant autre que Rempart.

## Profils mobiles (DoH, DoT)

**Interface sur le port DoH.** Réglages → Chiffrement → « Interface aussi sur le port DoH » sert l'interface sous `https://<nom du serveur>/`, à côté de `/dns-query`, sans port 8080 ni tunnel. Elle n'est servie qu'aux clients des réseaux autorisés (`dns.allowed_clients`) ; depuis Internet, même avec le port 443 redirigé pour DoH, elle répond 404. Ouvrez-la par un nom couvert par le certificat, pas par l'adresse IP. Pour un autre port (8443…), voir l'installeur (`--web-port`, `--web-lan`).

**Activer ou couper DoH, DoT, DoQ et DNSCrypt** : Réglages → Chiffrement. L'effet est immédiat, sans redémarrage. L'adresse et le port viennent de `doh.listen`, `dot.listen`, `doq.listen` et `dnscrypt.listen` dans le fichier de configuration, parce qu'ils doivent correspondre aux ports publiés par le conteneur (443, 853/tcp et 853/udp, dans l'unité Quadlet comme dans `docker-compose.yml`).

- **DNS-over-QUIC** (RFC 9250, ALPN `doq`, TLS 1.3, sans 0-RTT) partage le certificat de DoT et DoH.
- **DNSCrypt v2** : XChaCha20-Poly1305 (et XSalsa20-Poly1305 pour les anciens clients). La clé de fournisseur Ed25519 (`rempart-dnscrypt`) est créée dans le keystore, HSM compris ; les clés de résolveur X25519 changent toutes les heures et ne sont jamais écrites sur disque. L'interface donne le tampon `sdns://` à copier dans dnscrypt-proxy ; `dnscrypt.stamp_addr` indique l'adresse publique à y annoncer. Désactivé tant que l'administrateur ne l'allume pas. Un port déjà pris est signalé dans la page et le choix n'est pas enregistré. Ce réglage n'est pas répliqué : chaque instance a ses propres écoutes.

Appareils → Profils mobiles crée pour chaque appareil une adresse DoH qui lui est propre, `https://<serveur>/dns-query/<jeton>` (jeton aléatoire de 160 bits). Rempart reconnaît l'appareil, lui applique la politique de son groupe et le sert même hors des réseaux de `dns.allowed_clients` : c'est ce qui permet de garder le filtrage en 4G ou à l'extérieur. Le jeton est affiché une fois ; seul son SHA-256 est conservé, comme pour les jetons d'API. Révocation et nouveau profil depuis la même page ; création réservée à l'interface.

- **iPhone, iPad, Mac** : profil `.mobileconfig` (charge utile `com.apple.dnsSettings.managed`), signé en CMS par le certificat de l'interface (la clé reste dans le keystore ou le HSM). L'appareil l'affiche « vérifié » quand ce certificat vient d'une AC qu'il reconnaît (ACME, PKI déployée) ; avec le certificat auto-signé, il reste « non vérifié ». L'AC de votre PKI peut y être jointe ; l'utilisateur doit encore l'approuver dans Réglages des certificats.
- **Android 9 et plus** : le DNS privé n'accepte que DoT et un nom d'hôte. Rempart lit un jeton dans le premier label du nom TLS (`<jeton>.dns.example`). Il faut un certificat couvrant `*.dns.example`, un enregistrement générique `*` dans la zone publique (vers l'adresse publique) et dans une zone locale de Rempart (vers l'adresse locale). Ce nom circule en clair (résolution préalable par le résolveur du moment, ClientHello). Par défaut, il identifie seulement l'appareil sur les réseaux autorisés. L'option **« DoT depuis Internet avec le jeton d'appareil »** (Réglages → Chiffrement, désactivée par défaut) lui fait ouvrir l'accès depuis Internet, port 853 redirigé, pour garder le filtrage en 4G sans application. Le risque à accepter : qui observe le ClientHello (opérateur mobile, Wi-Fi public) peut réutiliser le jeton pour se servir du résolveur, avec la politique de cet appareil, sans voir ses requêtes ni les zones internes. Le jeton se révoque depuis l'interface. Sans cette option, utilisez hors du réseau une application DoH (RethinkDNS par exemple) avec l'adresse de l'appareil.
- **Windows 11, Firefox, Chrome** : l'adresse DoH comme serveur DNS chiffré personnalisé.

Le certificat auto-signé est refusé par ces clients : utilisez ACME ou votre PKI (Sécurité → Certificat). L'adresse DoH d'un appareil est un secret : quiconque la connaît peut utiliser le résolveur avec la politique de ce groupe, rien de plus. Un client admis par son seul jeton (hors des réseaux de `dns.allowed_clients`) n'obtient que la résolution publique : les zones locales lui sont refusées et les noms DHCP ne lui sont pas servis. Ni l'interface ni l'API ne lui sont ouvertes.

## Serveur DHCP (facultatif)

Appareils → DHCP, pour les box qui ne permettent pas d'annoncer un autre DNS. Rempart attribue les adresses (RFC 2131 : DISCOVER, REQUEST, RENEW, DECLINE, RELEASE, INFORM), s'annonce comme serveur DNS et passerelle choisie, et rend chaque appareil joignable sous `<nom>.<domaine>` (A et PTR). Baux statiques par adresse MAC. Désactivez d'abord le DHCP de la box.

- Les baux (adresses MAC, noms d'appareils) sont scellés sur disque comme l'état, et suivent les rotations de KEK et la migration vers le HSM.
- Le domaine des appareils ne peut pas recouvrir une zone locale signée (les noms DHCP ne sont pas signés), ni être un domaine de premier niveau public. `home.arpa` (RFC 8375) est le choix recommandé.
- Les noms fournis par les appareils sont réduits à un label DNS (lettres, chiffres, tirets). Le premier appareil qui porte un nom le garde ; `wpad`, `isatap` et `localhost` sont refusés (détournement de la découverte de proxy).
- Défenses contre un hôte hostile du réseau : messages mal formés ignorés, débit plafonné (100 messages/s), table des baux bornée (deux fois la taille de la plage), DECLINE accepté du seul titulaire de l'adresse, écritures sur disque regroupées. Les relais DHCP (`giaddr`) ne sont pas pris en charge. Un fichier de baux illisible est mis de côté sans empêcher le démarrage.
- Linux seulement. Le conteneur doit partager le réseau de l'hôte pour recevoir les diffusions : dans l'unité Quadlet, remplacez les lignes `PublishPort=` par `Network=host` et retirez `Sysctl=` (réglez `net.ipv4.ip_unprivileged_port_start=53` sur l'hôte, ce qui couvre le port 67). Le socket est lié à l'interface choisie (`SO_BINDTODEVICE`), sans capacité depuis le noyau 5.7.

## Haute disponibilité : transferts de zone et réplication

Avec un seul serveur DNS, une panne coupe tout le réseau. Rempart propose deux mécanismes, combinables.

**Transferts de zone vers des secondaires** (Zones DNSSEC → une zone → Secondaires et mises à jour dynamiques). La zone part signée par AXFR (RFC 5936) vers les adresses déclarées, et un NOTIFY (RFC 1996) les prévient de chaque changement. Un IXFR reçoit les seules différences depuis la version du secondaire (RFC 1995), le seul SOA s'il est à jour, ou la zone complète si l'historique, gardé en mémoire, ne remonte pas assez loin (après un redémarrage par exemple). Les signatures des RRsets inchangés sont reprises d'une version à l'autre : une mise à jour ne re-signe que ce qui a changé, et l'IXFR reste petit même pour une zone signée. Toute opération exige à la fois une adresse autorisée et une signature TSIG valide (RFC 8945). Les transferts passent par TCP ou DoT, jamais par UDP. Le numéro de série avance à chaque modification et à chaque re-signature, pour que les secondaires récupèrent les nouvelles RRSIG avant leur expiration.

**Zones secondaires.** Rempart peut aussi copier la zone d'un primaire (BIND, Knot, Windows DNS, autre Rempart) et la servir telle quelle, signatures du primaire comprises. Chaque message du transfert doit être signé, et par la clé de la requête : un message non signé, ou signé d'une autre clé connue de Rempart (celle d'un éditeur RPZ par exemple), fait échouer le transfert. Un transfert est borné à 2 millions d'enregistrements. Rempart sert la copie scellée sur disque au redémarrage, rafraîchit selon le SOA ou sur NOTIFY signé, et cesse de servir une zone après son délai d'expiration sans contact (RFC 1035).

**Réplication** (Réglages → Exploitation). L'instance principale publie sa configuration de filtrage : listes, règles, groupes, appareils, résolution, flux RPZ et clés TSIG associées. La réplique la lit toutes les 30 secondes par `GET /api/sync`, avec un jeton de portée « sync », en TLS vérifié (l'AC d'une PKI interne se déclare en PEM). Elle reçoit les zones par AXFR signé, en zones secondaires gérées automatiquement. Seules les adresses déclarées comme répliques obtiennent la configuration et les transferts. Sur une réplique, la configuration recopiée est en lecture seule (HTTP 409). Restent propres à chaque instance : compte administrateur, annuaires, certificat, keystore, DHCP, journaux et statistiques, ainsi que les réglages de confidentialité (mode de journal, rétention, identification des clients, suggestions). La réplique ne reprend que les listes `https://` (jamais un chemin de fichier local), ne suit aucune redirection HTTP (le jeton ne part pas ailleurs) et ne laisse jamais une clé TSIG reçue remplacer une clé locale du même nom.

**Bascule et retour automatiques** (Réglages → Exploitation, deux instances). La réplique désignée prend le rôle principal « par intérim » quand l'instance principale reste injoignable pendant le délai choisi (5 minutes par défaut) : la configuration redevient modifiable pendant la panne. Chaque prise du rôle principal incrémente une époque, publiée par `GET /api/sync/role` ; une instance principale qui voit l'autre avec une époque plus grande redevient réplique et recopie sa configuration. Au retour de l'instance préférée, elle se resynchronise d'abord (les modifications faites pendant la panne sont conservées), puis reprend le rôle principal. Les deux instances ne sont jamais modifiables en même temps : c'est ce qui évite de perdre des modifications concurrentes.

Les secondaires et les répliques interrogent aussi le SOA de la zone en requête ordinaire : leur adresse doit figurer dans `dns.allowed_clients`.

| Clé TSIG | Usage |
|---|---|
| Algorithmes | HMAC-SHA256 (défaut), HMAC-SHA384, HMAC-SHA512 ; HMAC-MD5 et HMAC-SHA1 refusés |
| Secret | taille de la sortie du hachage (256, 384 ou 512 bits), aléatoire ; montré une fois avec les extraits BIND (aussi fichier de clé pour `nsupdate -k`, jamais `-y` qui met le secret sur la ligne de commande) et Knot, puis seulement dans l'état scellé |
| Import | clé d'un éditeur RPZ ou d'un primaire existant, 128 bits au moins |
| Vérification | l'algorithme est celui de la clé, jamais celui que le message annonce ; comparaison en temps constant |

Le secret TSIG doit rester utilisable pour calculer les HMAC : il est scellé avec l'état par la KEK (dans le HSM s'il y en a un), mais il n'est pas un objet non extractible du HSM. C'est conforme par équivalence à une clé HSM pour la protection au repos, pas en exécution.

Pour les clients, annoncez les deux serveurs : dans Appareils → DHCP, le champ « second serveur DNS » ajoute la réplique à l'option 6. Le DHCP n'est pas répliqué : deux serveurs DHCP sur un même réseau doivent se partager la plage (par exemple .100-.149 et .150-.199).

## Mises à jour dynamiques (RFC 2136)

Pour qu'un serveur DHCP (ISC, Kea, Windows) ou des postes enregistrent leur nom dans une zone interne signée. La zone choisit une clé TSIG de mise à jour, distincte de celle des transferts, et les adresses ou préfixes autorisés.

- Les prérequis (RFC 2136 §3.2) sont évalués sur la zone entière ; les codes de réponse sont ceux de la RFC (NXDOMAIN, YXDOMAIN, NXRRSET, YXRRSET, NOTZONE).
- Une mise à jour ne touche jamais les noms saisis par l'administrateur : ils renvoient REFUSED. Elle ne touche pas non plus SOA, NS de l'apex, ni les enregistrements DNSSEC, gérés par Rempart.
- DNAME est refusé, ainsi que NS et DS sur un nom placé au-dessus d'un nom de l'administrateur : chez les secondaires, cette délégation ou cette réécriture le masquerait.
- Bornes : 10 000 enregistrements dynamiques par zone, 20 mises à jour acceptées par seconde.
- Les enregistrements dynamiques sont conservés à part dans l'état scellé et visibles dans l'interface. La zone est re-signée, le numéro de série avance et un NOTIFY part vers les secondaires.
- Anti-rejeu : une requête signée déjà acceptée est refusée jusqu'à la fin de sa validité (heure de signature + fudge). Un fudge de plus de 300 s est refusé. La mémoire anti-rejeu est scellée sur disque (`tsig-replay.sealed`) avant le traitement de la mise à jour : elle survit à un redémarrage, et une écriture impossible fait refuser la mise à jour. Une mémoire illisible au démarrage fait refuser les mises à jour pendant la fenêtre TSIG. Chaque mise à jour est inscrite dans l'audit (`tsig:<clé>`).

## Flux de menaces (RPZ)

Filtrage → Flux RPZ. Les Response Policy Zones (format BIND et Knot Resolver) sont reçues par AXFR signé TSIG (rafraîchissement selon le SOA, et sur NOTIFY signé de l'éditeur) ou par HTTPS au format fichier de zone (`$INCLUDE` et `$GENERATE` refusés, 256 Mo et 2 millions d'enregistrements au plus, redirections vers autre chose que `https://` refusées). La chaîne de requête de l'URL, qui porte souvent la clé d'accès de l'éditeur, n'est jamais renvoyée par l'API ni écrite dans les erreurs. La dernière copie est scellée sur disque et protège dès le démarrage, même sans réseau.

| Déclencheur | Prise en charge |
|---|---|
| QNAME (nom exact, `*.` pour les sous-domaines) | ✅ |
| QNAME appliqué aux cibles CNAME de la réponse | ✅ (un nom listé ne se cache pas derrière un alias) |
| Adresse de réponse (`rpz-ip`, IPv4 et IPv6) | ✅, réponses du cache comprises |
| Adresse du client (`rpz-client-ip`) | ✅, évalué avant le QNAME dans un même flux |
| Serveurs de noms du domaine (`rpz-nsdname`, joker compris ; `rpz-nsip`) | ✅ : Rempart ne faisant pas de résolution itérative, il cherche par requêtes NS les serveurs de la zone la plus proche qui contient le nom (cache de 10 minutes), puis leurs adresses si un flux a des déclencheurs `rpz-nsip`. Aucune requête en plus sans ce type de déclencheur |

Actions : NXDOMAIN (`CNAME .`), NODATA (`CNAME *.`), PASSTHRU, DROP (requête abandonnée, mais inscrite au journal), TCP-ONLY, réécriture CNAME et données locales. Les flux s'appliquent à tous les appareils, avant les groupes et leurs exceptions, pendant les pauses aussi ; le premier flux de la liste qui correspond l'emporte. Un PASSTHRU n'écarte que les flux placés après le sien. Écart avec la spécification : les déclencheurs QNAME du nom demandé sont évalués avant ceux de la réponse (cibles CNAME, adresses), qui ne sont connus qu'après la résolution. C'est conforme par équivalence à l'ordre des zones de BIND, sauf quand un flux plus prioritaire ne déclenche que sur la réponse pour un nom qu'un flux moins prioritaire déclenche par QNAME.

## Supervision

**Prometheus.** `GET /metrics` sur l'interface d'administration, avec un jeton de portée « metrics » (ou « read »). Métriques disponibles :

- requêtes par issue et par transport, histogramme de latence ;
- cache, résolveurs en amont ;
- règles par liste et date de mise à jour, flux RPZ ;
- zones (série, expiration des signatures), secondaires (dernier transfert, expiration) ;
- expiration du certificat, intégrité du journal d'audit (vérification gardée 5 minutes) ;
- DHCP, file de la copie syslog, réplication, mémoire.

Aucune métrique ne porte l'adresse ni le nom d'un appareil.

```yaml
- job_name: rempart
  scheme: https
  authorization: { credentials_file: /etc/prometheus/rempart.token }
  tls_config: { ca_file: /etc/prometheus/ac-interne.pem }
  static_configs: [{ targets: ['rempart.maison.lan:8080'] }]
```

Alertes utiles : `rempart_audit_chain_ok == 0`, `rempart_zone_signature_expiry_timestamp_seconds - time() < 3*86400`, `rempart_tls_certificate_expiry_timestamp_seconds - time() < 14*86400`, `rempart_secondary_zone_expired == 1`, `rempart_rpz_error == 1`, `rempart_syslog_pending_events > 100`, `time() - rempart_replication_last_sync_timestamp_seconds > 300`.

**Audit vers un syslog ou un SIEM** (Réglages → Exploitation). Chaque événement du journal d'audit part en RFC 5424 (facilité 13, « log audit »). Le corps est l'événement JSON tel qu'il est signé (séquence, empreinte du précédent, signature), si bien que le SIEM peut vérifier la chaîne. Transports possibles :

- TLS (RFC 5425), certificat du collecteur vérifié ;
- TCP (RFC 6587, comptage d'octets) ;
- UDP (RFC 5426).

La copie relit le journal signé depuis la dernière position remise, enregistrée dans `audit-forward.json` : un collecteur injoignable ne fait perdre aucun événement, qui partent dans l'ordre à son retour. Après un arrêt brutal, jusqu'à 200 événements peuvent être envoyés deux fois (le numéro de séquence permet de les dédoublonner). Syslog n'a pas d'accusé de réception applicatif : un événement accepté par la pile TCP ou TLS puis perdu par le collecteur, ou un datagramme UDP perdu, ne sont pas renvoyés ; la chaîne de séquence révèle le trou côté SIEM. Choisir un transport en clair est inscrit dans l'audit.

## Sauvegarde et restauration

**Ce que contient une sauvegarde.** `GET /api/backup` (bouton dans Réglages → Exploitation, ou jeton de portée « backup ») produit une archive tar.gz qui contient :

- le dossier de données : état, audit et sa tête, journal des requêtes et clés du jour, baux DHCP, copies des zones secondaires et des flux RPZ, certificat ;
- le keystore logiciel, même s'il est hors du dossier de données ;
- un manifeste `MANIFEST.json` avec le SHA-256 de chaque fichier, la génération de KEK et le numéro du dernier événement d'audit.

Les copies des listes de blocage, retéléchargeables, sont exclues sauf avec `?lists=1`. Rien n'y est en clair qui ne l'était déjà sur disque : l'archive se range comme le dossier de données lui-même. L'archive est d'abord écrite dans un fichier temporaire du dossier de données, puis envoyée : les rotations de KEK et les reconfigurations du quorum n'attendent que la fin de l'écriture, et données et keystore viennent toujours de la même génération. Un journal qui grandit pendant la copie est sauvegardé jusqu'à sa taille au moment de son ouverture. Le manifeste détecte une archive corrompue ; contre une modification volontaire, l'intégrité repose sur le scellement des fichiers (les copies de listes et le certificat public ne sont pas scellés).

Un jeton « admin » ne permet pas de sauvegarder, car l'archive contient le keystore. Un jeton « backup » ne sert qu'à cela. Sauvegarde nocturne :

```bash
curl -fsS -H @/etc/rempart/backup.auth --cacert /etc/rempart/ac.pem \
  https://rempart.maison.lan:8080/api/backup -o /sauvegardes/rempart-$(date +%F).tar.gz
```

**Vérifier sans toucher au serveur.** La commande suivante contrôle les empreintes, ouvre le keystore de l'archive avec la phrase de passe, déchiffre l'état et chaque fichier scellé, et vérifie le journal d'audit :

```bash
podman run --rm --network none -v ./:/b:Z -v rempart-secrets:/run/secrets:ro \
  -e REMPART_KEYSTORE_PASSPHRASE_FILE=/run/secrets/keystore_passphrase \
  localhost/rempart backup verify -config /etc/rempart/rempart.yaml /b/rempart-2026-10-06.tar.gz
```

Sur une autre machine, créez d'abord le volume de secrets avec la phrase de l'installation sauvegardée (`setup-secrets` la demande, ne rien saisir en génère une neuve). Avec Docker, remplacez `podman` par `docker`, `localhost/rempart` par `rempart:latest` et retirez `:Z`.

En démarrage sous quorum, seules les empreintes sont vérifiables sans les dépositaires.

**Restaurer**, Rempart arrêté :

Le volume de données s'appelle `rempart_rempart-data` avec compose et `rempart-data` avec l'unité Quadlet.

```bash
podman run --rm --network none -v rempart-data:/var/lib/rempart -v ./:/b:Z \
  localhost/rempart restore -config /etc/rempart/rempart.yaml -force /b/rempart-2026-10-06.tar.gz
```

Les chemins de l'archive sont contrôlés (ni chemin absolu, ni `..`, ni lien), et chaque fichier doit correspondre au manifeste. Sans `-force`, un dossier non vide est refusé. Avec `-force`, son contenu est déplacé dans `.avant-restauration-<date>/`, jamais supprimé.

**À quel moment c'est sans risque.**

1. Restaurez toujours ensemble les données et le keystore de la même archive. Le `master.json` d'aujourd'hui ne déchiffre pas une archive dont la génération de KEK a été détruite depuis, et inversement.
2. Redémarrez avec la phrase de passe, ou le quorum, **en vigueur à la date de la sauvegarde**. Un dépositaire retiré depuis retrouve donc son rôle sur la copie restaurée. Après la restauration, refaites la reconfiguration du quorum pour le retirer de nouveau.
3. Les jours du journal des requêtes dont la clé avait déjà été détruite restent illisibles : c'est l'effacement cryptographique.
4. Avec un HSM, l'archive ne contient pas les clés. Il faut le token dans l'état de la même date, par la sauvegarde ou le clonage du constructeur.
5. Une archive restaurée sur une autre machine garde le rôle de réplication et les secondaires déclarés : vérifiez Réglages → Exploitation avant de la mettre sur le réseau.
6. Après une restauration, la copie vers le syslog repart du bon endroit : elle détecte un journal plus court et renvoie ce qu'il faut.

## Certificat de l'interface, de DoT et de DoH

La clé reste dans le keystore (dans le HSM s'il est configuré) ; seule une demande signée en sort. Sécurité → Certificat propose deux méthodes :

- **ACME (RFC 8555)**, avec n'importe quelle AC compatible : Let's Encrypt, EJBCA (`https://<serveur>/ejbca/acme/<alias>/directory`), EverTrust Horizon (`https://<serveur>/acme/<profil>/directory`), Smallstep, Vault… Liaison de compte externe (EAB) prise en charge ; la clé HMAC sert à l'inscription puis est effacée. Défi **http-01** (écoute temporaire sur `tls.acme_http_listen`) ou **dns-01**, publié par Rempart dans votre zone locale signée (adapté à une PKI interne dont l'AC interroge Rempart). Les AC internes se déclarent par leur certificat PEM : la vérification TLS n'est jamais désactivée. Renouvellement automatique au dernier tiers de la validité.
- **CSR et import** pour toute autre PKI : Rempart produit la CSR, vous importez la chaîne signée. Le certificat est contrôlé (correspondance avec la clé, ordre de la chaîne, `serverAuth`, `digitalSignature`) avant d'être mis en service à chaud.

## Rotation des clés DNSSEC

- **ZSK** : pré-publication (RFC 6781 §4.1.1.1), automatique tous les 90 jours par défaut.
- **KSK** : double signature du DNSKEY. La nouvelle KSK devient « prête » une fois propagée ; son DS est alors annoncé en CDS/CDNSKEY (RFC 7344, RFC 8078). Elle passe active quand le DS est constaté chez le parent ou confirmé à la main. Le constat automatique n'utilise qu'une réponse validée (bit AD) des résolveurs en amont. L'ancienne KSK continue de signer pendant au moins 24 h, ou plus si le TTL du DS observé l'exige, puis elle est détruite dans le keystore.
- **Changement d'algorithme** (par exemple ECDSA P-256 → Ed25519) : méthode prudente de la RFC 6781 §4.1.4. Les nouvelles clés signent d'abord sans être publiées, le temps que les caches reçoivent leurs signatures ; elles sont ensuite publiées ; le nouveau DS est attendu chez le parent (constaté ou confirmé à la main) ; les anciennes clés quittent le DNSKEY, puis leurs signatures disparaissent. À chaque étape, chaque RRset est signé dans chaque algorithme publié (RFC 4035 §2.2).
- **NSEC3** (RFC 5155) : les réponses négatives ne permettent plus d'énumérer les noms d'une zone interne. Paramètres de la RFC 9276 : SHA-1, aucune itération supplémentaire, sans sel, sans opt-out. Actif par défaut pour les nouvelles zones ; interrupteur dans « Rotation automatique ».
- Une clé active absente du keystore est une erreur : elle n'est jamais régénérée en silence.

## Clés d'accès (passkeys, WebAuthn)

Réglages → Compte → Clés d'accès. Passkeys de téléphone ou d'ordinateur, Windows Hello, Touch ID, clés FIDO2 (YubiKey, Nitrokey…), jusqu'à 10. L'inscription demande le mot de passe (et un code si le TOTP est actif) ; seule la clé publique est conservée, dans l'état scellé.

- **Second facteur** : après le mot de passe, la clé d'accès remplace le code à 6 chiffres.
- **Sans mot de passe** : « Se connecter avec une clé d'accès », accepté seulement si la clé a vérifié l'utilisateur (PIN, biométrie).
- Impossible à hameçonner : la clé ne signe que pour le nom de site sous lequel elle a été créée. Il faut donc ouvrir l'interface en HTTPS par son nom (`rempart.maison.lan`), pas par une adresse IP.
- Défis à usage unique liés à l'adresse du client ; compteur de signatures contrôlé (clé clonée détectée) ; échecs comptés dans le verrouillage anti-force brute.
- Vérification écrite sans dépendance (CBOR, COSE ES256, EdDSA et RS256). L'attestation n'est pas vérifiée : la clé est inscrite par un administrateur déjà authentifié.

## Double authentification (TOTP)

Réglages → Compte → Double authentification. Scannez le QR code (généré par le serveur, sans service externe) avec Aegis, 2FAS, Google ou Microsoft Authenticator, 1Password, Bitwarden…, confirmez avec un code et le mot de passe, puis conservez les 10 codes de secours affichés une seule fois.

- Le secret (160 bits) est rangé dans l'état scellé et n'est plus jamais renvoyé par l'API.
- Un code déjà accepté ne peut pas être rejoué ; chaque code de secours ne sert qu'une fois (seule leur empreinte est gardée).
- La connexion se fait en deux temps : le mot de passe donne un défi de 5 minutes lié à l'adresse IP, valable pour 5 essais ; les échecs comptent dans le verrouillage anti-force brute.
- Désactiver la double authentification ou renouveler les codes de secours demande le mot de passe et un code.
- Téléphone, clés d'accès et codes perdus : redémarrez une fois avec `REMPART_RESET_OTP=1`, qui retire le TOTP et les clés d'accès. La réinitialisation est inscrite dans l'audit ; retirez la variable ensuite.
- Les jetons d'API ne passent pas par le second facteur : ce sont des secrets à part entière.

## Sans HSM : quorum M sur N et rotation des clés

Le keystore logiciel suit la même hiérarchie qu'un coffre de clés : phrase de passe serveur et/ou quorum de dépositaires → **clé racine** (256 bits, aléatoire) → **KEK** par génération → clés de données (état, journal, tête d'audit) et clés de signature.

| Élément | Choix |
|---|---|
| Partage de la clé racine | Shamir sur GF(2^8), arithmétique en temps constant, 2 ≤ M ≤ N ≤ 16 |
| Part d'un dépositaire | chiffrée en AES-256-GCM par Argon2id(phrase du dépositaire), t=3, m=64 Mio, p=4 (RFC 9106) |
| KEK | AES-256-GCM, chiffrées par une sous-clé HKDF-SHA-256 de la clé racine |
| Intégrité de `master.json` | HMAC-SHA-256 (autre sous-clé HKDF) : seuil, mode, dépositaires ne se modifient pas sur disque |
| Liaison | chaque bloc chiffré porte en donnée associée l'identifiant de la clé racine et son rôle |

Sécurité → Quorum et rotation. La première **cérémonie** se fait par l'administrateur seul : chaque dépositaire tape sa phrase (12 caractères au moins), on choisit M et le mode :

- **Démarrage automatique** : la phrase serveur ouvre le keystore ; le quorum est exigé pour toute opération sensible et sert de secours si la phrase serveur est perdue.
- **Démarrage sous quorum** : après chaque redémarrage, Rempart ne sert rien tant que M dépositaires ne se sont pas présentés, chacun à son tour :

  ```bash
  podman exec -it rempart rempart unseal
  ```

  La phrase est lue au terminal sans écho et passe par un socket Unix 0600 (identité du pair vérifiée), jamais par la ligne de commande. Les parts reçues sont effacées après 15 minutes si le quorum n'est pas atteint. Ne configurez pas de redémarrage sur échec du contrôle de santé : il effacerait les parts déjà présentées.

Ensuite, changer les dépositaires, le seuil ou le mode, changer la période de rotation, ou détruire une ancienne KEK exige l'approbation de M dépositaires, vérifiée en reconstituant la clé racine. Pour une reconfiguration, les dépositaires approuvent un plan précis (mode, seuil, qui reste, qui arrive) et l'exécution doit lui correspondre. Les dépositaires conservés gardent leur phrase et la prouvent ; une reconfiguration ajoute moins de M nouveaux dépositaires, pour qu'aucun quorum ne se forme sans au moins un dépositaire déjà en place. Les noms de dépositaires sont en lettres latines, chiffres, espace et `-_.'` (pas de caractère invisible ni d'homoglyphe).

**Approbations au terminal seulement** (option de la cérémonie, recommandée dès que l'administrateur web n'est pas lui-même dépositaire). Les phrases ne passent plus par le navigateur de l'administrateur :

```bash
podman exec -it rempart rempart passwd    # chaque dépositaire fixe lui-même sa phrase (une fois)
podman exec -it rempart rempart approve   # affiche l'opération exacte, puis demande la phrase
```

Dans ce mode, une phrase saisie dans l'interface (cérémonie, nouveau dépositaire) ne compte pas tant que son titulaire ne l'a pas changée avec `rempart passwd` : l'interface signale qui doit encore le faire. Une approbation au terminal porte sur l'opération affichée ; si elle est remplacée pendant la saisie, l'approbation est refusée. Les essais sont limités par dépositaire et par canal.

**Révocation.** Toute reconfiguration crée une nouvelle clé racine et une KEK neuve, rechiffre les données, puis détruit les générations précédentes. Un ancien `master.json`, même avec les phrases de dépositaires retirés ou l'ancienne phrase serveur, n'ouvre donc aucune enveloppe écrite ensuite, et les sauvegardes antérieures du dossier de données deviennent illisibles (à savoir avant une restauration). Limite : le réchiffrement change l'enveloppe, pas les clés de données ni les clés de signature ; une copie antérieure d'un fichier, avec l'ancien `master.json` et M anciennes parts, en livre encore la clé. Après le retrait d'un dépositaire, renouvelez les clés DNSSEC (rotation) et le certificat TLS.

**Rotation des KEK** : planifiée (365 jours par défaut) ou à la demande. Rempart crée une KEK, rechiffre l'état, la tête d'audit, les clés du journal et les clés de signature, puis marque l'ancienne génération « retirée ». Sa destruction, sous quorum, rend illisibles les sauvegardes qu'elle chiffrait (effacement cryptographique). Un keystore de l'ancien format est converti au démarrage : l'ancienne clé maître devient la génération 0, une génération 1 neuve chiffre tout ce qui s'écrit ensuite, et la maintenance rechiffre puis retire la 0 (sa destruction reste sous quorum). Un keystore créé sans phrase de passe, démarré ensuite avec une, passe à une nouvelle clé racine et une KEK neuve.

Limites à connaître : en mode automatique, quelqu'un qui détient à la fois le disque et la phrase serveur ouvre le keystore sans quorum ; le quorum y est un contrôle d'autorisation de l'application. Seul le mode « démarrage sous quorum » rend la clé racine inaccessible sans M dépositaires, ce qui est conforme par équivalence au M sur N d'un HSM pour la protection au repos, mais pas en exécution : une fois déverrouillées, les clés sont dans la mémoire du processus (verrouillée, non « dumpable »), là où un HSM ne les expose jamais. En Go, la clé AES expansée d'un `cipher.AEAD` ne peut pas être effacée explicitement. Qui est root sur l'hôte peut aussi observer le terminal des dépositaires : séparez l'administration web de l'administration du serveur.

## Comptes d'entreprise : LDAP et OIDC (Keycloak)

Sécurité → Comptes et annuaires. Les administrateurs se connectent avec leur compte d'entreprise ; leur rôle dans Rempart découle de leurs groupes, relus à chaque connexion.

| Rôle | Droits |
|---|---|
| Administrateur | tout, y compris clés et HSM, quorum, jetons d'API et comptes externes |
| Opérateur | filtrage, zones et DNSSEC, résolution, certificat ; pas la sécurité |
| Lecture seule | consultation |

Un compte reconnu mais sans groupe associé à un rôle n'entre pas (même réponse qu'un mauvais mot de passe ; le motif est dans l'audit).

**Annuaire LDAP** (Active Directory, OpenLDAP, FreeIPA, 389-DS). Modèles préremplis dans l'interface.

- `ldaps://` ou `ldap://` avec StartTLS : aucune liaison en clair n'est possible, le certificat est toujours vérifié (AC interne déclarable en PEM). Plusieurs URL : essayées dans l'ordre.
- Le compte de service cherche l'utilisateur (`{user}` est échappé selon la RFC 4515 : pas d'injection de filtre), puis Rempart se lie avec le mot de passe saisi. Un mot de passe vide n'est jamais envoyé (liaison « non authentifiée »).
- Groupes par attribut (`memberOf`) et/ou par filtre (`(member={dn})`, ou `(member:1.2.840.113556.1.4.1941:={dn})` pour les groupes imbriqués d'AD).
- Quatre liaisons simultanées au plus ; les échecs comptent dans le verrouillage anti-force brute par adresse.

**OpenID Connect** (Keycloak, mais aussi Entra ID, Authentik, Okta…). Un bouton « Se connecter avec Keycloak » s'ajoute à la page de connexion.

- Code d'autorisation avec PKCE S256 ; `state` et `nonce` à usage unique, liés au navigateur par un cookie ; retour accepté 10 minutes.
- Jeton d'identité vérifié avec les clés du JWKS annoncé par la découverte : émetteur, audience, `azp`, dates, nonce. Algorithmes asymétriques seulement (RS, PS, ES, EdDSA) ; `none`, HS* et les en-têtes `jku`/`jwk`/`x5u` sont refusés. Rotation des clés du fournisseur suivie.
- Rôles lus dans la revendication choisie : `realm_access.roles` (défaut), `resource_access.<client>.roles` ou `groups`. Si Keycloak ne les met que dans le jeton d'accès, celui-ci est vérifié de la même façon (et doit être délivré à ce client).
- Niveau d'authentification exigible (`acr`), pour imposer l'OTP de Keycloak.
- La déconnexion termine aussi la session chez le fournisseur.

Côté Keycloak : client OpenID Connect `rempart`, authentification du client activée, *Standard flow* seul, PKCE S256, *Valid redirect URI* `https://<serveur>:8080/api/oidc/callback`, *Valid post logout redirect URI* `https://<serveur>:8080/`. L'interface rappelle ces étapes.

**Garde-fous.**

- Le compte local reste toujours utilisable : c'est l'accès de secours. Son nom va toujours au compte local, jamais à l'annuaire.
- Seul le compte local, avec son mot de passe (et un code TOTP s'il est actif), peut modifier ces réglages : un administrateur d'annuaire ne peut pas s'octroyer de droits. Un utilisateur externe ne peut pas non plus changer le mot de passe ni le second facteur du compte local.
- Le mot de passe du compte de service et le secret du client sont dans l'état scellé et ne sont jamais renvoyés par l'API. Ils doivent être ressaisis si l'URL de l'annuaire, le compte de service, l'émetteur ou le client changent : on ne peut pas les faire envoyer à un autre serveur.
- Enregistrer ces réglages ferme toutes les sessions ouvertes par l'annuaire ou le fournisseur.
- Chaque connexion, refus et modification est inscrit dans l'audit (`ldap:alice`, `oidc:alice`).

Aucune dépendance ajoutée : le client LDAP (`internal/identity/ldap`) et le client OIDC (`internal/identity/oidc`) sont écrits avec la bibliothèque standard de Go.

## Accès par API

Sécurité → Accès API crée des jetons porteurs (`Authorization: Bearer rmp_…`, 256 bits ; seul leur SHA-256 est conservé), avec des portées `read`, `tls`, `dnssec` et `admin`. Les jetons, le mot de passe et le HSM restent réservés à l'interface. Exemple, le jeton étant dans un fichier en 0600 :

```bash
curl -H @/run/secrets/rempart-auth https://rempart:8080/api/zones/maison.lan/ds?format=text
```

Points d'entrée utiles : `POST /api/tls/csr`, `POST /api/tls/certificate`, `POST /api/tls/acme/issue`, `GET /api/zones/{zone}/ds`, `POST /api/zones/{zone}/rollover`, `POST /api/zones/{zone}/ds-confirm`.

**Aide et console API.** L'interface sert deux pages, liées depuis son menu : `/aide.html`, l'aide complète, et `/api.html`, la console qui décrit les 124 routes de l'API (paramètres, corps, portée) et les exécute avec la session ou un jeton, en montrant la commande `curl` équivalente. `/openapi.json` (OpenAPI 3) sert à Postman ou à un générateur de client. Le catalogue est `web/static/api-spec.js` : un test (`web/apispec_test.go`) échoue si une route d'`internal/api/api.go` n'y figure pas ou n'a pas la même portée. Après modification, régénérez `openapi.json` avec `node scripts/gen-openapi.mjs`.

**Créer un jeton par script (installation automatisée).** Un compte administrateur, local ou LDAP, ouvre une session par `POST /api/login` (puis `POST /api/login/otp` si le TOTP est actif) et crée le jeton par `POST /api/tokens`. `scripts/rempart-token.sh` (et `rempart-token.ps1`) font tout. Le mot de passe est demandé au terminal sans écho, ou lu dans le fichier désigné par `REMPART_PASSWORD_FILE` (0600, par exemple un secret Ansible déchiffré), et le code TOTP dans `REMPART_OTP`. Aucune option ne désactive la vérification du certificat : déclarez l'AC (`--cacert`). Le jeton est écrit en 0600 sous forme d'en-tête pour `curl -H @fichier` :

```bash
./scripts/rempart-token.sh \
  -u https://rempart.maison.lan:8080 -n installation -s admin -d 1 -o /etc/rempart/api.auth --cacert ac.pem
```

Un jeton ne peut pas créer d'autre jeton : un jeton volé ne peut ni s'étendre ni se perpétuer.

## Résolution : profil personnel ou entreprise

Réglages → Résolution DNS. Le profil **personnel** propose des résolveurs publics chiffrés et indique leur juridiction : Quad9, DNS4EU, Mullvad, Cloudflare, Google. Le profil **entreprise** ajoute :
- les résolveurs internes ;
- le transfert conditionnel par domaine, par exemple vers les contrôleurs Active Directory, sans protection anti-rebinding sur ces domaines ;
- les AC internes pour valider les résolveurs DoT/DoH ;
- un bootstrap dédié.

Les changements s'appliquent à chaud.

## Validation DNSSEC locale

Réglages → Blocage → Protections → « Valider DNSSEC sur ce serveur » (actif par défaut). Rempart ne délègue plus la validation : il interroge ses résolveurs en amont avec les bits DO et CD, puis vérifie lui-même la chaîne de confiance, zone par zone, depuis l'ancre de la racine (DS de KSK-2017 et de KSK-2024 intégrés : la racine ne signe plus qu'avec KSK-2024 à partir du 11 octobre 2026).

- Signatures RSA/SHA-1, RSA/SHA-256 et SHA-512, ECDSA P-256 et P-384, Ed25519 ; une zone signée avec un algorithme inconnu est traitée comme non signée (RFC 4035 §5.2).
- Preuves de non-existence NSEC et NSEC3 (encloser le plus proche, opt-out), réponses synthétisées depuis un joker, CNAME et DNAME. Un NSEC3 de plus de 100 itérations est traité comme non sécurisé (RFC 9276).
- Une réponse falsifiée (signature invalide ou absente dans une zone signée, preuve manquante, DS retiré par un intermédiaire) est refusée : SERVFAIL avec l'erreur étendue 6 « DNSSEC Bogus » (RFC 8914) et son motif, inscrite au journal.
- Le bit AD n'est posé que sur une réponse validée par Rempart, et seulement pour un client qui a envoyé DO ou AD (RFC 6840 §5.8) ; il n'est plus recopié depuis l'amont. Un client qui envoie CD reçoit la réponse brute, qui n'est pas mise en cache.
- Les domaines transférés vers un serveur interne (Réglages → Résolution DNS) sont des ancres négatives (RFC 7646). Des zones internes signées peuvent être ancrées par leur DS : `dnssec.trust_anchors` dans `rempart.yaml`.
- Les TTL sont bornés par le TTL d'origine signé et par l'expiration des signatures. La chaîne de confiance est gardée en cache une heure au plus ; « Vider le cache DNS » la vide aussi.

Métrique : `rempart_dnssec_validations_total{result="secure|insecure|bogus"}`.

## Ma liste et suggestions

Filtrage → Ma liste accepte l'import en masse (domaines, hosts, Adblock) et exporte la liste aux formats Adblock, hosts et domaines. Filtrage → Suggestions, une fois activé dans Réglages → Confidentialité, analyse en mémoire les noms résolus, sans rien noter des appareils, et propose de bloquer :
- les CNAME vers une infrastructure de traçage connue ;
- les sous-domaines dont les voisins sont déjà bloqués ;
- les noms typiques de la publicité ou de la télémétrie ;
- les noms aléatoires inexistants, signe possible d'un logiciel malveillant.

Rien ne quitte le serveur.

## Architecture

```
client ─▶ ACL (ou jeton d'appareil) ─▶ limite de débit ─▶ zones locales (DNSSEC) ─▶ noms DHCP
       ─▶ RPZ (QNAME) ─▶ groupe : règles, plages horaires, services, SafeSearch ─▶ listes du groupe ─▶ cache
                                                                          │
                       journal (selon le mode) ◀─ anti-rebinding ◀─ anti-CNAME ◀─ validation DNSSEC ◀─ upstreams DoH/DoT
```

| Dossier | Rôle |
|---|---|
| `internal/keystore` | abstraction des clés : logiciel (Argon2id + AES-GCM) ou PKCS#11 |
| `internal/zones` | zones faisant autorité, signature DNSSEC, NSEC et NSEC3, historique IXFR |
| `internal/filter`, `internal/blocker` | listes hosts/Adblock, recherche par suffixe, mises à jour |
| `internal/upstream` | DoH, DoT (connexions réutilisées), UDP/TCP, course entre deux résolveurs |
| `internal/server` | pipeline DNS, écoute UDP (SO_REUSEPORT), TCP, DoT, DoH, DoQ, DNSCrypt |
| `internal/querylog` | modes de confidentialité, journal chiffré, effacement cryptographique |
| `internal/audit` | journal d'audit chaîné et signé |
| `internal/sealed`, `internal/state` | chiffrement par enveloppe de l'état |
| `internal/identity` | clients LDAP (BER, StartTLS) et OpenID Connect (PKCE, JWS) |
| `internal/policy` | groupes d'appareils, services, plages horaires, SafeSearch |
| `internal/dhcp` | serveur DHCPv4, baux scellés, noms des appareils |
| `internal/authority`, `internal/tsig` | AXFR/IXFR, NOTIFY, RFC 2136, zones secondaires, clés TSIG |
| `internal/rpz` | Response Policy Zones |
| `internal/replica` | synchronisation entre instances |
| `internal/metrics`, `internal/auditfwd` | Prometheus, copie de l'audit vers syslog/SIEM |
| `internal/backup` | sauvegarde, vérification, restauration |
| `internal/dnssec` | validation DNSSEC locale (chaîne de confiance, NSEC, NSEC3) |
| `internal/dnscrypt` | protocole DNSCrypt v2 (certificats, chiffrement, tampons) |
| `internal/webauthn` | clés d'accès : CBOR, COSE, vérification des signatures |
| `internal/cms` | signature CMS des profils Apple |
| `internal/api`, `web/` | API REST et interface web (CSP stricte, sans dépendance) |

**Performances mesurées :** ~140 ns pour tester un domaine contre 500 000 règles, ~340 ns pour traiter une requête servie depuis le cache. Les signatures DNSSEC sont calculées au chargement de la zone, jamais à chaque requête : le HSM n'est pas un goulot d'étranglement.

## Confidentialité

Le mode se règle dans l'interface (Réglages → Confidentialité) :

- **Aucun journal** : seulement des compteurs anonymes.
- **Statistiques anonymes** (défaut) : compteurs, plus les domaines bloqués les plus fréquents. Rien par appareil.
- **Journal complet chiffré** : chaque requête est chiffrée en AES-256-GCM avec la clé du jour, elle-même chiffrée par le keystore. À l'expiration, la clé du jour est détruite et le journal devient illisible, même depuis une sauvegarde.

Chaque consultation d'une archive du journal est enregistrée dans l'audit.

## Développement

Prérequis : Go 1.24 et gcc pour le support HSM (sans gcc, le binaire est compilé sans HSM).

```bash
make test           # tests unitaires et de bout en bout
make test-hsm       # tests PKCS#11 réels (apt install softhsm2)
make run            # lance avec rempart.example.yaml
make build-nohsm    # binaire statique sans dépendance
```

Les dépendances sont vendorisées (`vendor/`) : la compilation fonctionne hors ligne. Seule dépendance ajoutée en 1.1 : `github.com/quic-go/quic-go` (DNS-over-QUIC). Ses empreintes dans `go.sum` ont été calculées sans accès à `sum.golang.org` : sur un poste qui y accède, vérifiez-les une fois avec `rm go.sum && go mod tidy && git diff --exit-code go.sum`.

## Limites actuelles (v1.1)

- La réplication garde une seule instance modifiable à la fois (bascule et retour automatiques, pas d'écriture simultanée sur deux instances). Les zones locales restent signées par l'instance principale ; une réplique les sert en zones secondaires.
- Les déclencheurs RPZ `rpz-nsdname` et `rpz-nsip` portent sur les serveurs de la zone la plus proche qui contient le nom, trouvés par requêtes NS ; un résolveur itératif les évaluerait à chaque délégation du chemin.
- L'historique IXFR est gardé en mémoire : après un redémarrage, un secondaire en retard reçoit une fois la zone complète.
- Passer d'un HSM à un autre suppose un clonage par l'outil du constructeur : les clés non extractibles ne sortent jamais d'un HSM par Rempart.
- Les ancres de confiance de la racine sont intégrées au binaire (pas de suivi automatique RFC 5011) ; une nouvelle clé de la racine demandera une mise à jour de Rempart ou `dnssec.trust_anchors`.
- Le compte local est le seul à disposer du TOTP et des clés d'accès de Rempart ; pour les comptes LDAP et OIDC, la double authentification relève de l'annuaire ou de Keycloak.
- Les rôles d'une session externe sont fixés à la connexion : un retrait de groupe prend effet à la reconnexion (ou à l'expiration de la session, `web.session_ttl`).
- Les statistiques sont gardées en mémoire et remises à zéro au redémarrage, par choix de confidentialité.
