package dnsclient

import (
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"

	"github.com/miekg/dns"
)

// siteLocalV6 is the deprecated IPv6 site-local range (RFC 3879). Windows
// still auto-assigns fec0:0:0:ffff::1-3 as DNS servers on some interfaces even
// when no such resolver exists.
var siteLocalV6 = netip.MustParsePrefix("fec0::/10")

// DetectSystemDNS returns the resolvers currently configured on this machine,
// ready to be benchmarked. Detection is best-effort: when it is not possible
// the feature degrades to an empty list rather than failing the run.
func DetectSystemDNS() []string {
	var ips []string
	if runtime.GOOS == "windows" {
		ips = windowsDNS()
	} else {
		ips = resolvConfDNS()
	}

	seen := make(map[string]struct{}, len(ips))
	var out []string
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, err := netip.ParseAddr(ip); err != nil {
			continue
		}
		if _, dup := seen[ip]; dup {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

// windowsDNS reads the currently effective DNS servers via PowerShell.
func windowsDNS() []string {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-DnsClientServerAddress -AddressFamily IPv4,IPv6).ServerAddresses")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseWindowsDNSOutput(string(out))
}

// parseWindowsDNSOutput extracts the addresses from PowerShell output and drops
// the legacy site-local addresses Windows adds to some IPv6 interfaces.
func parseWindowsDNSOutput(out string) []string {
	var addresses []string
	for address := range strings.FieldsSeq(out) {
		if addr, err := netip.ParseAddr(address); err == nil && siteLocalV6.Contains(addr) {
			continue
		}
		addresses = append(addresses, address)
	}
	return addresses
}

// resolvConfDNS parses a resolv.conf(5)-style file.
func resolvConfDNS() []string {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	return cfg.Servers
}

// SystemDNSLabel builds the display name of the n-th detected system resolver.
func SystemDNSLabel(index, total int) string {
	if total <= 1 {
		return "当前系统 DNS"
	}
	return fmt.Sprintf("当前系统 DNS %d", index+1)
}
