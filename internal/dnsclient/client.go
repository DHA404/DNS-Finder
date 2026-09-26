// Package dnsclient implements the DNS query transports used by the
// benchmark: plain UDP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH) and
// DNS-over-HTTP/3 (DoH3).
//
// A Querier is used by exactly one goroutine at a time and keeps its
// connection state alive across queries, so that the latency of a query
// measures one round trip rather than a fresh handshake every time (see
// PLAN 3.2). Every Querier must be primed with Warmup before the measured
// queries start.
package dnsclient

import (
	"fmt"
	"strings"
	"time"

	"dns-opti/internal/config"
	"dns-opti/internal/model"
)

// LookupResult is the raw outcome of one A query, kept uninterpreted so the
// caller can apply its own policy (the detection treats NXDOMAIN, an empty
// answer and a sinkhole address as blocking, and a transport failure as "no
// evidence").
type LookupResult struct {
	// Rcode is the DNS response code (0 = NOERROR, 3 = NXDOMAIN).
	Rcode int
	// RcodeText is the human-readable form of Rcode.
	RcodeText string
	// Addrs are the A records in the answer section, in wire order.
	Addrs []string
}

// Answered reports whether the resolver produced a DNS response at all, as
// opposed to the query failing at the transport layer.
func (r LookupResult) Answered() bool { return r.RcodeText != "" }

// Options controls how a single server is queried.
type Options struct {
	// Timeout bounds one query (including the connection setup when the
	// connection had to be rebuilt).
	Timeout time.Duration
	// WarmupDomain is queried once before measurement. Its result is
	// discarded; it only establishes and validates the connection.
	WarmupDomain string
	// Family is the address family to use for hostname-based servers. The
	// empty value leaves the choice to the local network, preferring a family
	// that is actually reachable.
	Family model.IPVersion
}

// Querier performs queries against one DNS server.
type Querier interface {
	// Query sends one A query for domain and reports how long it took. A
	// failed query also reports its elapsed time, which is not used for
	// latency statistics.
	Query(domain string) (time.Duration, error)
	// Lookup returns the raw outcome of one A query: the response code and the
	// addresses in the answer section.
	//
	// It exists for the resolver type detection, which has to tell "this name
	// was deliberately refused" from "this resolver did not answer". Query
	// collapses both into a single error, which is exactly the distinction the
	// detection depends on, so it cannot be built on top of Query.
	Lookup(domain string) (LookupResult, error)
	// Warmup primes the connection. Its error is advisory: a failed warm-up
	// counts as the first strike towards declaring a server unreachable.
	Warmup() error
	// Family reports the address family actually dialled. For a literal
	// endpoint it is the endpoint's own family; for a hostname it is the family
	// the name resolved to, which is what makes an IPv6 run verifiable rather
	// than merely configured.
	Family() model.IPVersion
	// ResolvedIP reports the literal address the endpoint is reached at: the
	// endpoint itself for a bare IP, or the address a hostname resolved to.
	//
	// It is what lets every surface identify a server by IP. The value is only
	// known once the transport has been built, because a hostname endpoint's
	// address comes from a lookup; an endpoint that could not be resolved
	// reports an empty string rather than pretending to have one.
	ResolvedIP() string
	// Close releases the connection resources of this server.
	Close() error
}

// New builds a Querier for server. The caller owns the returned Querier and
// must Close it.
//
// When the server is pinned to one address family but opts requests the other,
// the server cannot be tested as configured; that is reported as an error so
// the scheduler records the entry as a failure rather than silently measuring
// a different address than the user asked for.
func New(server model.Server, opts Options) (Querier, error) {
	if opts.Timeout <= 0 {
		// Fall back to the shared default rather than a local copy, so a caller
		// that builds Options directly cannot silently measure with a different
		// timeout than the one the tool documents.
		opts.Timeout = config.DefaultTimeout
	}
	if f := FamilyOf(server.Address); f.IsLiteral() && opts.Family.IsLiteral() && f != opts.Family {
		return nil, fmt.Errorf("服务器 %s 是 %s 地址，与请求的 %s 不符",
			server.Address, f.Label(), opts.Family.Label())
	}
	switch server.Protocol {
	case model.ProtocolUDP, model.ProtocolDoT:
		return newStreamQuerier(server, opts), nil
	case model.ProtocolDoH, model.ProtocolDoH3:
		return newHTTPSQuerier(server, opts)
	default:
		return nil, fmt.Errorf("不支持的协议: %s", server.Protocol)
	}
}

// warmupName returns the domain to prime a connection with.
func warmupName(opts Options) string {
	if strings.TrimSpace(opts.WarmupDomain) == "" {
		return "example.com"
	}
	return strings.TrimSpace(opts.WarmupDomain)
}
