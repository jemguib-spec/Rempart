// profile.go - profils de configuration DNS des appareils : .mobileconfig
// Apple (iOS 14+, macOS 11+) pointant vers l'URL DoH propre à l'appareil.
package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"fmt"

	"github.com/rempart-dns/rempart/internal/state"
)

func uuid4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// mobileConfig produit un profil non signé (l'appareil l'affiche « non
// vérifié »). ca, s'il est fourni, ajoute l'AC de la PKI interne, que
// l'utilisateur doit encore approuver dans Réglages → Informations →
// Réglages des certificats.
func mobileConfig(dev state.Device, dohURL string, ca []byte) string {
	if dohURL == "" {
		return ""
	}
	dnsUUID, profUUID := uuid4(), uuid4()
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
`)
	if ca != nil {
		caUUID := uuid4()
		fmt.Fprintf(&b, `		<dict>
			<key>PayloadCertificateFileName</key>
			<string>rempart-ca.cer</string>
			<key>PayloadContent</key>
			<data>%s</data>
			<key>PayloadDisplayName</key>
			<string>AC du serveur Rempart</string>
			<key>PayloadIdentifier</key>
			<string>dns.rempart.ca.%s</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
`, base64.StdEncoding.EncodeToString(ca), caUUID, caUUID)
	}
	fmt.Fprintf(&b, `		<dict>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>HTTPS</string>
				<key>ServerURL</key>
				<string>%s</string>
			</dict>
			<key>PayloadDisplayName</key>
			<string>Rempart DNS</string>
			<key>PayloadIdentifier</key>
			<string>com.apple.dnsSettings.managed.%s</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Résolution DNS chiffrée par Rempart (DNS-over-HTTPS), filtrage compris.</string>
	<key>PayloadDisplayName</key>
	<string>Rempart DNS – %s</string>
	<key>PayloadIdentifier</key>
	<string>dns.rempart.profile.%s</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, xmlText(dohURL), dnsUUID, dnsUUID, xmlText(dev.Name), dev.ID, profUUID)
	return b.String()
}
