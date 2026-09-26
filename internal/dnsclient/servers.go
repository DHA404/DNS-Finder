package dnsclient

import (
	"net/netip"
	"strings"

	"dns-opti/internal/model"
	"dns-opti/internal/policy"
	"dns-opti/internal/region"
)

// FilterReachable drops literal addresses that cannot be tested: ones whose
// address family this host has no route for, and ones whose family contradicts
// an explicit --ip-version request.
//
// Hostnames are always kept: they may resolve to either family, and the
// resolution step picks a reachable one.
//
// The probe is skipped when it cannot change the answer — see
// FilterReachableNeeding.
func FilterReachable(servers []model.Server, want model.IPVersion) (kept []model.Server, skipped int) {
	return FilterReachableNeeding(servers, want)
}

// FilterReachableNeeding is FilterReachable, but it only pays for the
// reachability probe when that probe can actually change the outcome.
//
// The probe is not free: on a host whose IPv6 path is broken it has to wait out
// the full timeout to conclude "no IPv6". Running it for a list that contains
// no IPv6 literal, or for an explicit --ip-version ipv4 (where reachability is
// not consulted at all), would spend that time to learn something the filter
// never uses. Both cases are common — every IPv4-only run hits one of them.
func FilterReachableNeeding(servers []model.Server, want model.IPVersion) (kept []model.Server, skipped int) {
	if !probeWouldMatter(servers, want) {
		return filterReachable(servers, want, NetworkCapabilities{})
	}
	return filterReachable(servers, want, DetectCapabilities())
}

// probeWouldMatter reports whether the reachability verdict can affect the
// filtering of this list.
//
// It cannot when the family was requested explicitly (the request overrides
// reachability), and it cannot when every literal endpoint belongs to a single
// family that the probe would never drop — a list of only IPv4 literals is
// filtered by neither an IPv4 verdict nor an IPv6 one, because dropping only
// happens for the family that failed.
func probeWouldMatter(servers []model.Server, want model.IPVersion) bool {
	if want.IsLiteral() {
		return false
	}
	hasV4, hasV6 := false, false
	for _, s := range servers {
		switch FamilyOf(s.Address) {
		case model.IPv4:
			hasV4 = true
		case model.IPv6:
			hasV6 = true
		}
		if hasV4 && hasV6 {
			return true
		}
	}
	// A single-family literal list is only affected if that family can fail.
	// Both families can, so this is exactly "does the list hold any literal at
	// all". Hostname-only lists are never filtered, so they need no probe.
	return hasV4 || hasV6
}

// filterReachable is the capability-injected core of FilterReachable, so the
// filtering rules can be tested deterministically without depending on whether
// the machine running the tests has IPv6 transit.
//
// An explicit --ip-version is a deliberate user instruction and therefore
// *disables* the reachability half for that family: if someone asks for IPv6,
// silently testing nothing would be worse than testing servers that turn out
// not to answer. The run reports the failures, which is the informative
// outcome. Without such a request the probe is trusted, because it exists to
// stop a broken path from turning every IPv6 server into a long stall.
//
// The reachability half is also skipped when neither family could be probed: an
// offline run, a sandbox that blocks UDP dialling or a container without a
// default route would otherwise have every literal-address server dropped with
// no explanation.
func filterReachable(servers []model.Server, want model.IPVersion, cap NetworkCapabilities) (kept []model.Server, skipped int) {
	explicit := want.IsLiteral()
	filterFamily := !explicit && (cap.IPv4 || cap.IPv6)

	kept = make([]model.Server, 0, len(servers))
	for _, s := range servers {
		family := FamilyOf(s.Address)
		if !family.IsLiteral() {
			kept = append(kept, s)
			continue
		}
		if explicit && family != want {
			skipped++
			continue
		}
		if filterFamily && !cap.isReachableFamily(mustAddr(s.Address)) {
			skipped++
			continue
		}
		kept = append(kept, s)
	}
	return kept, skipped
}

// FamilyFilter reports whether a literal endpoint may be tested, applying the
// same rule to every kind of server.
//
// It exists so the built-in list, the machine's own resolvers and any explicit
// --servers entry are all judged identically. Before it, system resolvers were
// filtered only by an explicit --ip-version, so a host whose IPv6 path the
// probe had just declared dead still went on to test its IPv6 resolvers — and
// paid a full timeout each to record a guaranteed failure.
type FamilyFilter func(address string) bool

// NewFamilyFilter builds the family predicate for a run.
//
// An explicit --ip-version is an instruction and is honoured exactly: only that
// family passes. Otherwise the probed reachability decides, except that an
// inconclusive probe (neither family usable — an offline host, a sandbox that
// blocks UDP) restricts nothing, because dropping every literal server on the
// strength of a failed probe would empty the run.
func NewFamilyFilter(want model.IPVersion) FamilyFilter {
	if want.IsLiteral() {
		return func(address string) bool {
			family := FamilyOf(address)
			// A hostname has no fixed family, so it is never excluded here;
			// resolution picks a reachable one.
			return !family.IsLiteral() || family == want
		}
	}

	cap := DetectCapabilities()
	if !cap.IPv4 && !cap.IPv6 {
		return func(string) bool { return true }
	}
	return func(address string) bool {
		family := FamilyOf(address)
		if !family.IsLiteral() {
			return true
		}
		return cap.isReachableFamily(mustAddr(address))
	}
}

// mustAddr parses the host of a literal endpoint. The caller has already
// established that it is a literal (FamilyOf returned IPv4 or IPv6), so a parse
// failure is impossible; an unparsable value is treated as the zero Addr, which
// is unreachable and therefore dropped.
func mustAddr(endpoint string) netip.Addr {
	addr, err := netip.ParseAddr(hostOf(endpoint))
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

// ParseServers parses an explicit comma-separated server list, inferring each
// entry's protocol from its prefix, preserving the input order and dropping
// duplicates. It is the escape hatch for testing servers that are not in the
// built-in inventory:
//
//	host or IP                  -> udp://host:53
//	[2606:4700::1111]           -> UDP over IPv6
//	udp://host                  -> UDP
//	tls://host                  -> DoT
//	https://host/path           -> DoH
//	h3://host/path              -> DoH3 (rewritten to https:// for the request)
//
// A bare IPv6 literal may be written with or without brackets.
func ParseServers(raw string) ([]model.Server, error) {
	seen := make(map[string]struct{})
	var out []model.Server
	for entry := range strings.SplitSeq(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		s, ok := parseServer(entry)
		if !ok {
			continue
		}
		if _, dup := seen[s.Key()]; dup {
			continue
		}
		seen[s.Key()] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, errNoServers
	}
	return out, nil
}

// parseServer turns one user-supplied entry into a Server.
func parseServer(entry string) (model.Server, bool) {
	switch {
	case strings.HasPrefix(entry, "h3://"), strings.HasPrefix(entry, "doh3://"):
		addr := dohEndpoint(entry[strings.Index(entry, "://")+3:])
		return newServer(hostOf(addr), addr, model.ProtocolDoH3), true

	case strings.HasPrefix(entry, "https://"), strings.HasPrefix(entry, "doh://"):
		addr := dohEndpoint(entry[strings.Index(entry, "://")+3:])
		return newServer(hostOf(addr), addr, model.ProtocolDoH), true

	case strings.HasPrefix(entry, "tls://"), strings.HasPrefix(entry, "dot://"):
		host := hostOf(entry)
		if host == "" {
			return model.Server{}, false
		}
		return newServer(host, host, model.ProtocolDoT), true

	case strings.HasPrefix(entry, "udp://"):
		host := hostOf(entry)
		if host == "" {
			return model.Server{}, false
		}
		return newServer(host, host, model.ProtocolUDP), true

	default:
		host := hostOf(entry)
		if host == "" {
			return model.Server{}, false
		}
		return newServer(host, host, model.ProtocolUDP), true
	}
}

// newServer assembles a server and fills in its derived region, family and
// policy.
func newServer(name, address string, protocol model.Protocol) model.Server {
	private := IsPrivateHost(address)
	return model.Server{
		Name:      name,
		Address:   address,
		Protocol:  protocol,
		Region:    region.Of(hostOf(address), private),
		Policy:    policy.OfServer(address, name),
		Family:    FamilyOf(address),
		IsPrivate: private,
	}
}

// dohEndpoint normalises the remainder of a DoH/DoH3 entry into an https URL,
// expanding a bare host to the RFC 8484 /dns-query endpoint. A bracketed IPv6
// literal is preserved as an authority.
func dohEndpoint(rest string) string {
	if !strings.Contains(rest, "/") {
		rest += "/dns-query"
	}
	return "https://" + rest
}

// MarkSpecial annotates the servers with the flags the report and the viewer
// need: whether the entry is the machine's configured resolver, whether it is
// an internal (private / loopback / link-local) address, and its derived
// region, filtering policy and address family.
func MarkSpecial(servers []model.Server) []model.Server {
	out := make([]model.Server, len(servers))
	for i, s := range servers {
		s.IsPrivate = IsPrivateHost(s.Address)
		if s.Region == "" {
			s.Region = region.Of(hostOf(s.Address), s.IsPrivate)
		}
		if s.Policy == "" {
			s.Policy = policy.OfServer(s.Address, s.Name)
		}
		if s.IP == "" {
			// A literal endpoint is its own address; a hostname is left empty
			// here because only resolution can supply its address, and the
			// scheduler fills it in once the transport is built.
			s.IP = literalOrEmpty(s.Address)
		}
		if s.Family == "" {
			s.Family = FamilyOf(s.Address)
		}
		out[i] = s
	}
	return out
}

// ComboPair describes one provider measured over two transports.
type ComboPair struct {
	// Key is the shared identifier of the pairing.
	Key string
	// Primary and Secondary are the two servers of the pair. Either may be
	// zero-valued when the provider only publishes one of the two transports.
	Primary, Secondary model.Server
}

// PairUDPDoH groups the UDP and DoH servers of the same provider so the two
// transports can be compared directly. A server is matched by its Normalized
// provider identity: for a curated inventory entry the display name is used
// (both "AliDNS" entries share it), and otherwise a hostname stem is derived
// from the address.
//
// Servers that have no counterpart still come back, paired with a zero value,
// so a provider available over only one transport is not silently dropped.
func PairUDPDoH(servers []model.Server) []ComboPair {
	type pair struct {
		srv      map[model.Protocol]model.Server
		order    []model.Protocol
		provider string
	}
	groups := map[string]*pair{}
	var order []string

	for _, s := range servers {
		if s.Protocol != model.ProtocolUDP && s.Protocol != model.ProtocolDoH {
			continue
		}
		key := providerIdentity(s)
		g, ok := groups[key]
		if !ok {
			g = &pair{srv: map[model.Protocol]model.Server{}, provider: key}
			groups[key] = g
			order = append(order, key)
		}
		if _, dup := g.srv[s.Protocol]; dup {
			continue
		}
		g.srv[s.Protocol] = s
		g.order = append(g.order, s.Protocol)
	}

	out := make([]ComboPair, 0, len(order))
	for _, key := range order {
		g := groups[key]
		out = append(out, ComboPair{
			Key:       key,
			Primary:   g.srv[model.ProtocolUDP],
			Secondary: g.srv[model.ProtocolDoH],
		})
	}
	return out
}

// providerIdentity reduces a server to the provider it belongs to, so that its
// UDP and DoH endpoints land in the same bucket.
//
// The display name is preferred, because the inventory already uses one name
// per provider ("AliDNS 1" for UDP, "AliDNS" for DoH, both reducing to
// "alidns"). It is combined with the region so that two unrelated providers
// sharing a generic name are never merged. When the name is absent the leading
// label of the hostname is used, which maps "dns.alidns.com" and
// "https://dns.alidns.com/dns-query" onto the same identity.
func providerIdentity(s model.Server) string {
	stem := providerStem(s.Name)
	if stem == "" {
		stem = hostStem(s.Address)
	}
	if stem == "" {
		return ""
	}
	return stem + "|" + region.Normalize(s.Region)
}

// hostStem derives a provider identity from an endpoint address: the first
// label of the host, with the transport-ish prefixes stripped so that
// dns./dot./doh. do not split one provider into two identities.
func hostStem(address string) string {
	lower := strings.ToLower(hostOf(address))
	for _, prefix := range []string{"dns.", "dot.", "doh.", "dns-", "one."} {
		lower = strings.TrimPrefix(lower, prefix)
	}
	if i := strings.IndexByte(lower, '.'); i > 0 {
		return lower[:i]
	}
	return lower
}

// providerStem normalises a display name into a provider identity: the
// transport word and the trailing index are removed, so "AliDNS 1 (IPv6)" and
// "AliDNS" both reduce to "alidns".
func providerStem(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	// Drop a bracketed qualifier such as "(IPv6)".
	if i := strings.IndexByte(name, '('); i >= 0 {
		name = name[:i]
	}
	// Drop the transport words used by the inventory's encrypted entries.
	for _, word := range []string{"doh3", "doh", "dot", "udp", "ipv6", "ipv4", "tls"} {
		name = strings.ReplaceAll(name, word, "")
	}
	// Drop a trailing index ("alidns 1" -> "alidns").
	name = strings.TrimRight(name, " 0123456789")
	name = strings.TrimSpace(strings.Trim(name, "-_/"))
	return name
}

// ProviderIdentity is the exported form of providerIdentity, used by the engine
// to stamp the pairing of a combined run. It returns an empty string for a
// server that cannot be identified, which keeps such a server unpaired.
func ProviderIdentity(s model.Server) string { return providerIdentity(s) }

// errNoServers is returned when an explicit server list parses to nothing.
var errNoServers = errorString("未解析出任何有效的 DNS 服务器")

// errorString is a minimal error type so this package has no external error
// dependency for a single static message.
type errorString string

func (e errorString) Error() string { return string(e) }
