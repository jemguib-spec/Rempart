package api

import (
	"strings"
	"testing"
	"time"
)

const (
	ovhSecret   = "SecretSecretSecretSecret01234567"
	ovhConsumer = "ConsumerConsumerConsumer01234567"
)

func ovhCfg(zone, secret, consumer string) string {
	return `{"names":["dns.example.fr","*.dns.example.fr"],"acme":{"directory_url":"https://acme-staging-v02.api.letsencrypt.org/directory","challenge":"dns-01",` +
		`"dns":{"provider":"ovh","zone":"` + zone + `","ovh_endpoint":"ovh-eu","ovh_app_key":"AbCdEf0123456789","ovh_app_secret":"` + secret + `","ovh_consumer_key":"` + consumer + `"}}}`
}

func TestACMEDNSProviderSecrets(t *testing.T) {
	c, a := newTestAPI(t)
	code, body := c.do("PUT", "/api/tls/config", ovhCfg("example.fr", ovhSecret, ovhConsumer))
	if code != 200 {
		t.Fatal(body)
	}
	if strings.Contains(body, ovhSecret) || strings.Contains(body, ovhConsumer) {
		t.Fatal("secret renvoyé par l'API")
	}
	if !strings.Contains(body, `"ovh_app_secret":true`) || !strings.Contains(body, `"*.dns.example.fr"`) {
		t.Fatalf("drapeaux ou joker absents : %s", body)
	}
	if d := a.Store.Get().TLS.ACME.DNS; d.OVHAppSecret != ovhSecret || d.OVHConsumerKey != ovhConsumer {
		t.Fatalf("secret non scellé : %+v", d)
	}
	// Enregistrer sans ressaisir garde les secrets.
	if code, body := c.do("PUT", "/api/tls/config", ovhCfg("example.fr", "", "")); code != 200 {
		t.Fatal(body)
	}
	if a.Store.Get().TLS.ACME.DNS.OVHAppSecret != ovhSecret {
		t.Fatal("secret perdu")
	}
	// Autre zone : les secrets ne suivent pas sans ressaisie.
	if code, body := c.do("PUT", "/api/tls/config", ovhCfg("autre.fr", "", "")); code != 400 || !strings.Contains(body, "ressaisissez") {
		t.Fatalf("%d %s", code, body)
	}
	// Passage à Cloudflare : les clés OVH sont effacées.
	cf := `{"names":["dns.example.fr"],"acme":{"directory_url":"https://acme-staging-v02.api.letsencrypt.org/directory","challenge":"dns-01","dns":{"provider":"cloudflare","zone":"example.fr","cloudflare_token":"cf-0123456789abcdef"}}}`
	if code, body := c.do("PUT", "/api/tls/config", cf); code != 200 {
		t.Fatal(body)
	}
	if d := a.Store.Get().TLS.ACME.DNS; d.OVHAppSecret != "" || d.CloudflareToken != "cf-0123456789abcdef" {
		t.Fatalf("%+v", d)
	}
	// Joker refusé avec http-01.
	wild := `{"names":["*.dns.example.fr"],"acme":{"directory_url":"https://acme-staging-v02.api.letsencrypt.org/directory","challenge":"http-01"}}`
	if code, body := c.do("PUT", "/api/tls/config", wild); code != 400 || !strings.Contains(body, "dns-01") {
		t.Fatalf("%d %s", code, body)
	}
	bad := `{"names":["a.*.example.fr"],"acme":{"directory_url":"https://x/directory","challenge":"dns-01"}}`
	if code, _ := c.do("PUT", "/api/tls/config", bad); code != 400 {
		t.Fatal("joker hors du premier label accepté")
	}
	// Configuration incomplète pour dns-01 : refusée.
	inc := `{"names":["dns.example.fr"],"acme":{"directory_url":"https://x/directory","challenge":"dns-01","dns":{"provider":"cloudflare","zone":"autre.fr"}}}`
	if code, _ := c.do("PUT", "/api/tls/config", inc); code != 400 {
		t.Fatal("jeton manquant accepté")
	}
}

func TestACMEIssueIsAsync(t *testing.T) {
	c, _ := newTestAPI(t)
	if code, body := c.do("POST", "/api/tls/acme/issue", ""); code != 202 || !strings.Contains(body, `"issuing"`) {
		t.Fatalf("%d %s", code, body)
	}
	// Sans compte, la tentative échoue vite et l'erreur est consignée.
	for range 100 {
		_, body := c.do("GET", "/api/tls", "")
		if strings.Contains(body, `"issuing":false`) {
			if !strings.Contains(body, "compte ACME non inscrit") {
				t.Fatalf("erreur non consignée : %s", body)
			}
			return
		}
		waitShort()
	}
	t.Fatal("la demande ne se termine pas")
}

func waitShort() { time.Sleep(20 * time.Millisecond) }
