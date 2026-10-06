package policy

// Service : application bloquable en un clic. Les domaines sont ceux dont
// l'application a besoin pour fonctionner (sites, API, CDN propres) ; un
// domaine partagé avec d'autres services (CDN génériques, comptes Google ou
// Microsoft) n'y figure pas, pour ne rien casser d'autre. Un sous-domaine
// (gemini.google.com) ne bloque que lui et ses propres sous-domaines.
type Service struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"` // identifiant d'un ServiceGroup
	Note     string   `json:"note,omitempty"`
	Domains  []string `json:"domains"`
}

// ServiceGroup : famille de services, présentée en bloc dans l'interface
// (tout cocher d'un coup, puis affiner service par service).
type ServiceGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Help string `json:"help"`
}

// ServiceGroups : ordre d'affichage des familles.
var ServiceGroups = []ServiceGroup{
	{"social", "Réseaux sociaux", "Fils d'actualité, stories, vidéos courtes."},
	{"video", "Vidéo et streaming", "Plateformes vidéo, direct, séries et films."},
	{"music", "Musique et audio", "Écoute en ligne et podcasts."},
	{"messaging", "Messageries", "Discussions et appels."},
	{"games", "Jeux en ligne", "Plateformes, boutiques et jeux en ligne."},
	{"ai", "Intelligence artificielle", "Assistants conversationnels."},
	{"shopping", "Achats en ligne", "Boutiques et places de marché."},
	{"dating", "Rencontres", "Applications de rencontre."},
}

func svc(id, name, cat, note string, domains ...string) Service {
	return Service{ID: id, Name: name, Category: cat, Note: note, Domains: domains}
}

// Services : catalogue intégré, sans téléchargement. Les identifiants sont
// stables (ils sont enregistrés dans l'état et répliqués) : ne jamais en
// renommer un, ni retirer un domaine qui affaiblirait un blocage existant.
var Services = []Service{
	// Réseaux sociaux
	svc("tiktok", "TikTok", "social", "", "tiktok.com", "tiktokv.com", "tiktokv.us", "tiktokv.eu", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokcdn-eu.com", "byteoversea.com", "ibytedtos.com", "ibyteimg.com", "byteimg.com", "muscdn.com", "musical.ly", "ttlivecdn.com", "tiktokrow-cdn.com"),
	svc("instagram", "Instagram", "social", "", "instagram.com", "cdninstagram.com", "ig.me", "igcdn.com", "instagr.am"),
	svc("threads", "Threads", "social", "Se connecte avec le compte Instagram : bloquer Instagram ne bloque pas Threads.", "threads.net", "threads.com"),
	svc("facebook", "Facebook et Messenger", "social", "Messenger passe par les serveurs de Facebook : les deux sont bloqués ensemble.", "facebook.com", "facebook.net", "fb.com", "fb.me", "fbcdn.net", "fbsbx.com", "messenger.com", "m.me"),
	svc("snapchat", "Snapchat", "social", "", "snapchat.com", "snap.com", "sc-cdn.net", "sc-static.net", "snap-dev.net", "snapkit.com", "snapads.com"),
	svc("twitter", "X (Twitter)", "social", "", "x.com", "twitter.com", "twimg.com", "t.co", "twttr.com", "twvid.com"),
	svc("bluesky", "Bluesky", "social", "", "bsky.app", "bsky.social", "bsky.network"),
	svc("reddit", "Reddit", "social", "", "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"),
	svc("pinterest", "Pinterest", "social", "", "pinterest.com", "pinterest.fr", "pinimg.com", "pin.it"),
	svc("bereal", "BeReal", "social", "", "bereal.com", "bere.al"),
	svc("tumblr", "Tumblr", "social", "", "tumblr.com"),
	svc("linkedin", "LinkedIn", "social", "", "linkedin.com", "licdn.com", "lnkd.in"),
	// Vidéo et streaming
	svc("youtube", "YouTube", "video", "Pour garder YouTube en mode restreint plutôt que le bloquer, voir Contrôle parental.", "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com", "youtubei.googleapis.com", "youtube.googleapis.com", "youtubekids.com", "yt.be", "youtube-ui.l.google.com", "wide-youtube.l.google.com"),
	svc("twitch", "Twitch", "video", "", "twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net", "ext-twitch.tv"),
	svc("kick", "Kick", "video", "", "kick.com"),
	svc("dailymotion", "Dailymotion", "video", "", "dailymotion.com", "dmcdn.net", "dai.ly"),
	svc("vimeo", "Vimeo", "video", "", "vimeo.com", "vimeocdn.com"),
	svc("netflix", "Netflix", "video", "", "netflix.com", "netflix.net", "nflxext.com", "nflximg.com", "nflximg.net", "nflxso.net", "nflxvideo.net"),
	svc("disneyplus", "Disney+", "video", "", "disneyplus.com", "disney-plus.net", "dssott.com", "bamgrid.com"),
	svc("primevideo", "Prime Video", "video", "Le site Amazon reste accessible.", "primevideo.com", "amazonvideo.com", "aiv-delivery.net", "aiv-cdn.net"),
	svc("max", "Max (HBO)", "video", "", "max.com", "hbomax.com"),
	svc("crunchyroll", "Crunchyroll", "video", "", "crunchyroll.com"),
	// Musique et audio
	svc("spotify", "Spotify", "music", "", "spotify.com", "scdn.co", "spotifycdn.com"),
	svc("deezer", "Deezer", "music", "", "deezer.com", "dzcdn.net"),
	svc("soundcloud", "SoundCloud", "music", "", "soundcloud.com", "sndcdn.com"),
	// Messageries
	svc("whatsapp", "WhatsApp", "messaging", "", "whatsapp.com", "whatsapp.net", "wa.me"),
	svc("telegram", "Telegram", "messaging", "", "telegram.org", "telegram.me", "t.me", "telegram.dog", "telesco.pe", "telegra.ph"),
	svc("discord", "Discord", "messaging", "", "discord.com", "discord.gg", "discord.media", "discordapp.com", "discordapp.net", "dis.gd"),
	svc("signal", "Signal", "messaging", "", "signal.org", "signal.me", "whispersystems.org"),
	// Jeux en ligne
	svc("roblox", "Roblox", "games", "", "roblox.com", "rbxcdn.com", "rbx.com", "rbxinfra.com", "robloxcdn.com"),
	svc("fortnite", "Fortnite et Epic Games", "games", "Fortnite se connecte par Epic Games : la boutique Epic est bloquée avec lui.", "epicgames.com", "epicgames.dev", "fortnite.com", "unrealengine.com"),
	svc("minecraft", "Minecraft", "games", "", "minecraft.net", "minecraftservices.com", "minecraft-services.net", "mojang.com"),
	svc("steam", "Steam", "games", "", "steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamserver.net", "steamgames.com", "steam-chat.com", "s.team"),
	svc("playstation", "PlayStation Network", "games", "", "playstation.com", "playstation.net", "sonyentertainmentnetwork.com"),
	svc("xbox", "Xbox Live", "games", "", "xboxlive.com", "xboxservices.com", "xbox.com", "gamepass.com"),
	svc("nintendo", "Nintendo en ligne", "games", "", "nintendo.net", "nintendo.com", "nintendo.fr", "nintendowifi.net"),
	svc("riot", "League of Legends et Valorant", "games", "Les deux jeux partagent le lanceur et les comptes Riot.", "riotgames.com", "leagueoflegends.com", "lolstatic.com", "playvalorant.com", "riotcdn.net"),
	svc("battlenet", "Battle.net (Blizzard)", "games", "", "battle.net", "blizzard.com"),
	svc("supercell", "Supercell (Clash, Brawl Stars)", "games", "", "supercell.com", "supercell.net"),
	svc("hoyoverse", "HoYoverse (Genshin Impact)", "games", "", "hoyoverse.com", "mihoyo.com", "hoyolab.com"),
	// Intelligence artificielle
	svc("chatgpt", "ChatGPT", "ai", "", "chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com"),
	svc("claude", "Claude", "ai", "", "claude.ai", "claudeusercontent.com"),
	svc("gemini", "Gemini", "ai", "Le reste de Google reste accessible.", "gemini.google.com", "bard.google.com"),
	svc("copilot", "Microsoft Copilot", "ai", "Le reste de Microsoft reste accessible.", "copilot.microsoft.com"),
	svc("mistral", "Le Chat (Mistral)", "ai", "", "chat.mistral.ai"),
	svc("perplexity", "Perplexity", "ai", "", "perplexity.ai", "pplx.ai"),
	svc("characterai", "Character.AI", "ai", "", "character.ai"),
	// Achats en ligne
	svc("shein", "Shein", "shopping", "", "shein.com", "shein.fr", "ltwebstatic.com"),
	svc("temu", "Temu", "shopping", "", "temu.com", "kwcdn.com"),
	svc("aliexpress", "AliExpress", "shopping", "", "aliexpress.com", "aliexpress.us", "aliexpress-media.com"),
	svc("vinted", "Vinted", "shopping", "", "vinted.com", "vinted.fr", "vinted.net"),
	// Rencontres
	svc("tinder", "Tinder", "dating", "", "tinder.com", "gotinder.com"),
	svc("bumble", "Bumble", "dating", "", "bumble.com"),
	svc("hinge", "Hinge", "dating", "", "hinge.co"),
}

// ServiceByID renvoie un service du catalogue.
func ServiceByID(id string) (Service, bool) {
	for _, s := range Services {
		if s.ID == id {
			return s, true
		}
	}
	return Service{}, false
}

// Category : liste publique proposée en un clic pour un groupe (contrôle
// parental). Ce sont des listes ordinaires, téléchargées et vérifiées comme
// les autres.
type Category struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Help string `json:"help"`
	URL  string `json:"url"`
}

var Categories = []Category{
	{"adult", "Contenus pour adultes", "Sites pornographiques et pour adultes (HaGeZi NSFW).", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nsfw.txt"},
	{"gambling", "Jeux d'argent", "Paris en ligne, casinos, loteries (HaGeZi Gambling).", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/gambling.txt"},
	{"social", "Réseaux sociaux", "L'ensemble des réseaux sociaux, au-delà du catalogue de services (HaGeZi Social).", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/social.txt"},
	{"nosafesearch", "Moteurs sans SafeSearch", "Moteurs de recherche qui ne savent pas imposer le filtrage (HaGeZi No SafeSearch).", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nosafesearch.txt"},
	{"bypass", "Contournement", "DoH publics, VPN, proxys et Tor : sans ce blocage, un appareil peut ignorer Rempart (HaGeZi DoH/VPN/Proxy Bypass).", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-vpn-proxy-bypass.txt"},
	{"threats", "Menaces", "Hameçonnage, logiciels malveillants, arnaques (HaGeZi Threat Intelligence Feeds).", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt"},
}
