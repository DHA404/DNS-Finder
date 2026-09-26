package dnsclient

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"dns-opti/internal/model"
)

// NetworkCapabilities describes which IP address families this host can
// actually reach.
type NetworkCapabilities struct {
	IPv4 bool
	IPv6 bool
}

// canDialUDP reports whether a socket for network can be created towards
// address. Dialling a UDP socket sends no packet and contacts no server; it
// only asks the kernel to pick a route and a source address.
//
// This check alone is *not* sufficient to conclude that a family is usable.
// A host behind a router that advertises a global IPv6 prefix but provides no
// IPv6 transit has a valid route and a source address, so dialling succeeds,
// yet every packet is dropped and every query times out — which is precisely
// the environment that would otherwise turn dozens of IPv6 servers into
// dozens of five-second stalls. It is kept as a cheap pre-filter; the active
// probe below is what decides.
func canDialUDP(network, address string) bool {
	conn, err := net.Dial(network, address)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Probe budget and targets.
const (
	// probeTimeout bounds a single probe query. It is deliberately shorter than
	// a normal query timeout: a healthy resolver answers in well under a
	// second, and this cost is paid once per process before any measurement.
	probeTimeout = 1500 * time.Millisecond
	// probeHostname is the name asked in the probe query. Its answer is
	// discarded; only "did anything come back" matters.
	probeHostname = "example.com"
)

// probeTargets are the addresses the capability probe tries, per family.
//
// Several *diverse* targets are used per family, and the family counts as
// reachable as soon as any one of them answers. A single target would be
// actively wrong: public resolvers are routinely blocked by a network or its
// upstream while the family itself works perfectly — 1.1.1.1 is unreachable
// from large parts of the world, and probing only it would report a healthy
// IPv4 host as having no IPv4, silently discarding every IPv4 server. Mixing
// domestic and international targets makes that misjudgement far less likely.
var probeTargets = map[model.IPVersion][]string{
	model.IPv4: {"223.5.5.5:53", "8.8.8.8:53", "1.1.1.1:53"},
	model.IPv6: {"[2400:3200::1]:53", "[2001:4860:4860::8888]:53", "[2606:4700:4700::1111]:53"},
}

// queryProbe sends one real query and reports whether a response came back.
// The context lets a probe be abandoned as soon as another target of the same
// family has already answered. It is a separate type so the capability logic
// can be tested without a network.
type queryProbe func(ctx context.Context, network, address string, timeout time.Duration) bool

// canQuery sends one UDP DNS query over the given network to address and
// reports whether a well-formed answer arrived within timeout. Unlike a dial,
// this proves the packet actually made a round trip.
func canQuery(ctx context.Context, network, address string, timeout time.Duration) bool {
	client := &dns.Client{Net: network, Timeout: timeout, UDPSize: 1232}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(probeHostname), dns.TypeA)

	resp, _, err := client.ExchangeContext(ctx, msg, address)
	if err != nil || resp == nil {
		return false
	}
	// Any well-formed reply proves reachability; a SERVFAIL still means the
	// server is there. Only a missing or malformed reply counts as unreachable.
	return resp.Response
}

// probeCapabilities reports which address families are genuinely usable: at
// least one probe target of that family answers a real query.
//
// Three properties matter here, and each of them was a real defect before:
//
//  1. A query, not a dial, decides. A host behind a router that advertises a
//     global IPv6 prefix but provides no transit has a valid route and source
//     address, so dialling succeeds while every packet is dropped.
//  2. Several targets per family, and any one of them suffices. A single
//     well-known resolver is routinely blocked by a network or its upstream, so
//     probing only one would report a healthy family as unusable.
//  3. The first answer cancels the remaining probes of that family. Without
//     cancellation the family still waits out the whole timeout whenever any
//     one target is blackholed — and a partially blocked family is the common
//     case, so that wait would land on almost every run.
//
// Both families are probed concurrently, so the total cost is bounded by the
// slower family rather than by the sum of the two.
func probeCapabilities(canDial func(network, address string) bool, canQuery queryProbe) NetworkCapabilities {
	var (
		wg  sync.WaitGroup
		cap NetworkCapabilities
		mu  sync.Mutex
	)

	probeFamily := func(family model.IPVersion) {
		defer wg.Done()

		network := socketNetwork("udp", family)
		targets := probeTargets[family]

		// A dial failure means the kernel has no route for this family at all,
		// which no query can fix; skip the queries and the wait.
		if !canDial(network, targets[0]) {
			return
		}

		// ctx is cancelled by the first target that answers, which abandons the
		// in-flight queries of the others immediately instead of waiting for
		// them to time out.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var (
			hit     bool
			hitOnce sync.Once
			inner   sync.WaitGroup
		)
		for _, target := range targets {
			inner.Add(1)
			go func(target string) {
				defer inner.Done()
				if canQuery(ctx, network, target, probeTimeout) {
					hitOnce.Do(func() {
						hit = true
						cancel()
					})
				}
			}(target)
		}
		inner.Wait()

		mu.Lock()
		if family == model.IPv4 {
			cap.IPv4 = hit
		} else {
			cap.IPv6 = hit
		}
		mu.Unlock()
	}

	wg.Add(2)
	go probeFamily(model.IPv4)
	go probeFamily(model.IPv6)
	wg.Wait()

	return cap
}

// capabilities caches the probe result. The override is kept behind the same
// mutex so that a test replacing the verdict cannot race with the concurrent
// workers that call DetectCapabilities.
var (
	capabilitiesOnce sync.Once
	capabilitiesVal  NetworkCapabilities
	capabilitiesMu   sync.Mutex
	capabilitiesFix  *NetworkCapabilities
)

// DetectCapabilities returns the usable IP address families. The probe runs at
// most once per process, and its result is cached; the two families are probed
// concurrently, so the cost is one short query rather than two.
func DetectCapabilities() NetworkCapabilities {
	capabilitiesMu.Lock()
	override := capabilitiesFix
	capabilitiesMu.Unlock()
	if override != nil {
		return *override
	}

	capabilitiesOnce.Do(func() {
		capabilitiesVal = probeCapabilities(canDialUDP, canQuery)
	})
	return capabilitiesVal
}

// SetCapabilitiesForTest replaces the capability verdict and returns a function
// that restores the original behaviour. It exists so tests can exercise the
// address-family filtering deterministically, without depending on whether the
// machine running them happens to have working IPv6 transit. It is not meant
// for production code, which should always go through DetectCapabilities.
func SetCapabilitiesForTest(c NetworkCapabilities) (restore func()) {
	capabilitiesMu.Lock()
	previous := capabilitiesFix
	fix := c
	capabilitiesFix = &fix
	capabilitiesMu.Unlock()

	return func() {
		capabilitiesMu.Lock()
		capabilitiesFix = previous
		capabilitiesMu.Unlock()
	}
}

// IsPrivate reports whether addr is a local / internal resolver: an RFC 1918
// or RFC 4193 private address, a loopback address or an IPv6 link-local
// address. Such resolvers usually serve internal names (VPN, corporate or
// router-local), so switching away from them can break name resolution; the
// tool flags them instead of recommending a switch (see PLAN 九).
func IsPrivate(addr string) bool {
	ip, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// IsPrivateHost applies IsPrivate to an endpoint of any shape (bare host, host
// with port, bracketed IPv6, DoH URL). It is the single place that decides
// whether an endpoint is internal, so the region table and the private-address
// warning can never disagree.
func IsPrivateHost(endpoint string) bool { return IsPrivate(hostOf(endpoint)) }

// FamilyOf reports the address family of a literal endpoint, or IPAny when the
// endpoint is a hostname (whose family is decided at resolve time).
func FamilyOf(endpoint string) model.IPVersion {
	host := hostOf(endpoint)
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4() {
			return model.IPv4
		}
		return model.IPv6
	}
	return model.IPAny
}

// isReachableFamily reports whether a literal address belongs to a family this
// host can route.
func (c NetworkCapabilities) isReachableFamily(addr netip.Addr) bool {
	if addr.Is4() {
		return c.IPv4
	}
	return c.IPv6
}

// MatchesFamily reports whether a capability set can attempt endpoints of the
// requested family. IPAny never restricts anything.
func (c NetworkCapabilities) MatchesFamily(f model.IPVersion) bool {
	switch f {
	case model.IPv4:
		return c.IPv4
	case model.IPv6:
		return c.IPv6
	}
	return true
}

// selectResolvedHost picks the address to dial from a host's resolved
// addresses. When a specific family was requested and the name has an address
// of that family, it is used; otherwise the choice falls back to whichever
// family the local network can reach, and finally to the first address.
func selectResolvedHost(addrs []string, cap NetworkCapabilities, want model.IPVersion) string {
	// An explicit request wins whenever the name can satisfy it.
	switch want {
	case model.IPv4:
		if picked, ok := pickFamily(addrs, true); ok {
			return picked
		}
	case model.IPv6:
		if picked, ok := pickFamily(addrs, false); ok {
			return picked
		}
	}

	if cap.IPv4 {
		if picked, ok := pickFamily(addrs, true); ok {
			return picked
		}
	}
	if cap.IPv6 {
		if picked, ok := pickFamily(addrs, false); ok {
			return picked
		}
	}
	if len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}

// pickFamily returns the first address of the requested family.
func pickFamily(addrs []string, wantV4 bool) (string, bool) {
	for _, candidate := range addrs {
		addr, err := netip.ParseAddr(candidate)
		if err != nil {
			continue
		}
		if addr.Is4() == wantV4 {
			return candidate, true
		}
	}
	return "", false
}

// resolveHost resolves a hostname to a single IP address of a family this host
// supports. The result is cached for the lifetime of the process so that the
// system resolver is contacted at most once per (name, family); resolution time
// is never counted towards a query's latency.
func resolveHost(host string, timeout time.Duration, want model.IPVersion) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return host
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return host // already a literal address
	}
	return resolveCached(host, timeout, want)
}

// resolvedEntry caches one lookup.
type resolvedEntry struct {
	ip  string
	err error
}

// resolveKey identifies a cached lookup: the same name may be resolved
// differently for IPv4 and IPv6, so the family is part of the key.
type resolveKey struct {
	host   string
	family model.IPVersion
}

var (
	resolveMu    sync.Mutex
	resolveCache = map[resolveKey]resolvedEntry{}
)

// resolveCached performs the actual lookup once per (host, family).
func resolveCached(host string, timeout time.Duration, want model.IPVersion) string {
	key := resolveKey{host: host, family: want}

	resolveMu.Lock()
	if e, ok := resolveCache[key]; ok {
		resolveMu.Unlock()
		if e.err != nil {
			return host
		}
		return e.ip
	}
	resolveMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addrs, err := lookupFor(ctx, host, want)
	entry := resolvedEntry{err: err}
	if err == nil && len(addrs) > 0 {
		entry.ip = selectResolvedHost(addrs, DetectCapabilities(), want)
	} else if err == nil {
		entry.err = context.DeadlineExceeded
	}

	resolveMu.Lock()
	resolveCache[key] = entry
	resolveMu.Unlock()

	if entry.err != nil {
		return host
	}
	return entry.ip
}

// lookupFor resolves host, asking the system resolver only for the requested
// family when one was given. Restricting the query is what makes
// --ip-version ipv6 work for a hostname endpoint: the resolver is asked for
// AAAA records, so a dual-stack name cannot silently resolve to IPv4.
func lookupFor(ctx context.Context, host string, want model.IPVersion) ([]string, error) {
	switch want {
	case model.IPv4:
		addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		return ipStrings(addrs), err
	case model.IPv6:
		addrs, err := net.DefaultResolver.LookupIP(ctx, "ip6", host)
		return ipStrings(addrs), err
	default:
		return net.DefaultResolver.LookupHost(ctx, host)
	}
}

// ipStrings renders resolved IPs as strings.
func ipStrings(addrs []net.IP) []string {
	out := make([]string, 0, len(addrs))
	for _, ip := range addrs {
		out = append(out, ip.String())
	}
	return out
}

// hostOf extracts the host part of an endpoint. For URL-shaped endpoints
// (DoH/DoH3) it returns the authority without its port when the default port
// is used; for plain "host", "host:port" and bracketed IPv6 forms it returns
// the host with the port stripped.
func hostOf(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if i := strings.Index(endpoint, "://"); i >= 0 {
		endpoint = endpoint[i+3:]
	}
	if i := strings.IndexAny(endpoint, "/?#"); i >= 0 {
		endpoint = endpoint[:i]
	}
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		endpoint = h
	} else if strings.HasPrefix(endpoint, "[") && strings.HasSuffix(endpoint, "]") {
		endpoint = strings.TrimSuffix(strings.TrimPrefix(endpoint, "["), "]")
	}
	return endpoint
}
