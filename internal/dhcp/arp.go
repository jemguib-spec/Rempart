package dhcp

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// arpCache lit la table de voisinage du noyau (/proc/net/arp) pour les
// appareils à adresse fixe. Elle n'est complète qu'avec le réseau de l'hôte :
// dans un conteneur à réseau isolé, seuls les baux DHCP donnent la MAC.
type arpCache struct {
	mu   sync.Mutex
	at   time.Time
	byIP map[netip.Addr]string
}

const arpPath = "/proc/net/arp"

func (c *arpCache) lookup(ip netip.Addr) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) > 30*time.Second {
		c.byIP = readARP(arpPath)
		c.at = time.Now()
	}
	return c.byIP[ip]
}

// readARP : « IP address  HW type  Flags  HW address  Mask  Device ».
func readARP(path string) map[netip.Addr]string {
	out := map[netip.Addr]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // en-tête
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 4 || fs[2] == "0x0" { // entrée incomplète
			continue
		}
		ip, err1 := netip.ParseAddr(fs[0])
		hw, err2 := net.ParseMAC(fs[3])
		if err1 == nil && err2 == nil && len(hw) == 6 && hw.String() != "00:00:00:00:00:00" {
			out[ip] = hw.String()
		}
	}
	return out
}
