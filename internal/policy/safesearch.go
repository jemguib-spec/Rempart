package policy

import "strings"

// SafeSearch : les moteurs et YouTube imposent leur filtrage quand leur nom
// pointe vers une adresse dédiée (méthode documentée par chaque éditeur).
// Rempart répond par un CNAME vers cette cible, résolue normalement.
const (
	googleSafe     = "forcesafesearch.google.com."
	bingSafe       = "strict.bing.com."
	ddgSafe        = "safe.duckduckgo.com."
	yandexSafe     = "familysearch.yandex.ru."
	pixabaySafe    = "safesearch.pixabay.com."
	youtubeStrict  = "restrict.youtube.com."
	youtubeModerat = "restrictmoderate.youtube.com."
)

var safeExact = map[string]string{
	"bing.com.": bingSafe, "www.bing.com.": bingSafe,
	"duckduckgo.com.": ddgSafe, "www.duckduckgo.com.": ddgSafe, "start.duckduckgo.com.": ddgSafe,
	"yandex.ru.": yandexSafe, "www.yandex.ru.": yandexSafe, "yandex.com.": yandexSafe, "www.yandex.com.": yandexSafe, "ya.ru.": yandexSafe,
	"pixabay.com.": pixabaySafe, "www.pixabay.com.": pixabaySafe,
}

var youtubeNames = map[string]bool{
	"www.youtube.com.": true, "youtube.com.": true, "m.youtube.com.": true,
	"youtubei.googleapis.com.": true, "youtube.googleapis.com.": true, "www.youtube-nocookie.com.": true,
}

// SafeTarget renvoie la cible imposée pour name (FQDN en minuscules), ou "".
func SafeTarget(name string, safeSearch bool, youtube string) string {
	if youtube != "" && youtubeNames[name] {
		if youtube == "strict" {
			return youtubeStrict
		}
		return youtubeModerat
	}
	if !safeSearch {
		return ""
	}
	if t, ok := safeExact[name]; ok {
		return t
	}
	if isGoogleSearch(name) {
		return googleSafe
	}
	return ""
}

// isGoogleSearch reconnaît google.<tld> et www.google.<tld>, tld pouvant
// être « fr », « com », « co.uk » ou « com.br ».
func isGoogleSearch(name string) bool {
	n := strings.TrimSuffix(name, ".")
	n = strings.TrimPrefix(n, "www.")
	rest, ok := strings.CutPrefix(n, "google.")
	if !ok {
		return false
	}
	parts := strings.Split(rest, ".")
	switch len(parts) {
	case 1:
		return tldLike(parts[0])
	case 2:
		return (parts[0] == "co" || parts[0] == "com") && len(parts[1]) == 2 && tldLike(parts[1])
	}
	return false
}

func tldLike(s string) bool {
	if len(s) < 2 || len(s) > 3 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return true
}
