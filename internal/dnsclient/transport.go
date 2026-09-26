package dnsclient

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"

	"dns-opti/internal/model"
)

// streamQuerier queries a server over a stream / datagram transport handled by
// miekg/dns (plain UDP or DoT). It keeps one connection open and reuses it
// across queries, so a measurement reflects a single query round trip rather
// than a fresh handshake. A connection is used by one goroutine at a time.
type streamQuerier struct {
	server   model.Server
	opts     Options
	client   *dns.Client
	addr     string // resolved host:port actually dialled
	sni      string // TLS server name (DoT only)
	net      string // "udp4"/"udp6"/"udp" and "tcp4"/"tcp6"/"tcp"
	tcpRetry bool   // retry truncated UDP answers over TCP
	conn     *dns.Conn
}

// newStreamQuerier builds a querier for UDP and DoT.
func newStreamQuerier(server model.Server, opts Options) *streamQuerier {
	q := &streamQuerier{server: server, opts: opts}

	// A literal endpoint dictates the socket family (it can only be reached
	// over its own family); a hostname follows the configured option, which
	// may be empty meaning "let the network decide".
	family := FamilyOf(server.Address)
	if !family.IsLiteral() {
		family = opts.Family
	}
	q.net = socketNetwork("udp", family)

	host := hostOf(server.Address)
	switch server.Protocol {
	case model.ProtocolDoT:
		q.sni = host
		q.addr = net.JoinHostPort(resolveHost(host, opts.Timeout, family), "853")
		q.client = &dns.Client{Net: socketNetwork("tcp-tls", family), Timeout: opts.Timeout}
	default: // model.ProtocolUDP
		q.addr = net.JoinHostPort(resolveHost(host, opts.Timeout, family), "53")
		q.client = &dns.Client{Net: socketNetwork("udp", family), Timeout: opts.Timeout}
		q.tcpRetry = true
	}
	return q
}

// socketNetwork renders a miekg/dns network name for the given family. An empty
// or unknown family keeps the dual-stack name, which lets the kernel choose.
func socketNetwork(base string, family model.IPVersion) string {
	switch family {
	case model.IPv4:
		return base + "4"
	case model.IPv6:
		return base + "6"
	}
	return base
}

// Query sends one A query and reports the measured round trip.
func (q *streamQuerier) Query(domain string) (time.Duration, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	start := time.Now()
	resp, err := q.exchange(msg)
	if err != nil {
		// The peer may have closed an idle connection. Drop it and retry once
		// on a fresh connection; the timing is restarted so the measurement
		// reflects the retry.
		q.reset()
		start = time.Now()
		resp, err = q.exchange(msg)
	}
	elapsed := time.Since(start)

	if err != nil {
		q.reset()
		return elapsed, err
	}
	if resp.Truncated && q.tcpRetry {
		// A truncated UDP answer carries no usable data; repeat the query over
		// TCP. This is a property of the answer size, not a failure.
		if tcpResp, tcpErr := q.tcpExchange(msg); tcpErr == nil {
			resp = tcpResp
		} else {
			return elapsed, tcpErr
		}
	}
	if resp.Rcode != dns.RcodeSuccess {
		return elapsed, fmt.Errorf("DNS 响应码 %s", dns.RcodeToString[resp.Rcode])
	}
	return elapsed, nil
}

// Warmup primes the connection with the configured warm-up domain.
func (q *streamQuerier) Warmup() error {
	_, err := q.Query(warmupName(q.opts))
	return err
}

// Lookup returns the raw outcome of one A query.
//
// Unlike Query it does not retry on a stale connection and does not report a
// non-success response code as an error: the detection needs the code itself.
// It reuses the same persistent connection, so a probe costs one round trip.
func (q *streamQuerier) Lookup(domain string) (LookupResult, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	resp, err := q.exchangeOnce(msg)
	if err != nil {
		return LookupResult{}, err
	}
	return resultFromMsg(resp), nil
}

// exchangeOnce performs one query on the persistent connection, dialling it if
// necessary, and does not retry. Callers must not use it concurrently.
func (q *streamQuerier) exchangeOnce(msg *dns.Msg) (*dns.Msg, error) {
	if q.conn == nil {
		client := q.client
		if q.server.Protocol == model.ProtocolDoT {
			// Clone the client so the per-server TLS config is not shared
			// between goroutines.
			c := *q.client
			c.TLSConfig = tlsConfig(q.sni)
			client = &c
		}
		conn, err := client.Dial(q.addr)
		if err != nil {
			return nil, err
		}
		q.conn = conn
	}
	resp, _, err := q.client.ExchangeWithConn(msg, q.conn)
	return resp, err
}

// resultFromMsg extracts the raw outcome of a response.
func resultFromMsg(resp *dns.Msg) LookupResult {
	out := LookupResult{Rcode: resp.Rcode, RcodeText: dns.RcodeToString[resp.Rcode]}
	for _, a := range resp.Answer {
		if rr, ok := a.(*dns.A); ok {
			out.Addrs = append(out.Addrs, rr.A.String())
		}
	}
	return out
}

// Family reports the address family actually dialled: the endpoint's own family
// for a literal, or the family the hostname resolved to.
func (q *streamQuerier) Family() model.IPVersion {
	if f := FamilyOf(q.addr); f.IsLiteral() {
		return f
	}
	return FamilyOf(q.server.Address)
}

// ResolvedIP reports the literal address dialled.
//
// q.addr is a "host:port" pair whose host was already replaced by the resolved
// address in newStreamQuerier, so it is the authority of record. When the
// lookup failed, resolveHost returns the hostname unchanged and the family
// check below reports no literal — an honest "unknown" rather than a fabricated
// address.
func (q *streamQuerier) ResolvedIP() string {
	host := hostOf(q.addr)
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	// A literal endpoint whose port-stripping above did not apply (a bracketed
	// IPv6 authority) still yields its address through the server's own field.
	return literalOrEmpty(q.server.Address)
}

// literalOrEmpty returns the host of an endpoint when it is an IP literal, and
// an empty string otherwise.
func literalOrEmpty(endpoint string) string {
	host := hostOf(endpoint)
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	return ""
}

// Close releases the connection.
func (q *streamQuerier) Close() error {
	q.reset()
	return nil
}

// exchange performs one query on the persistent connection, dialling it if
// necessary. Callers must not use it concurrently.
func (q *streamQuerier) exchange(msg *dns.Msg) (*dns.Msg, error) {
	if q.conn == nil {
		client := q.client
		if q.server.Protocol == model.ProtocolDoT {
			// Clone the client so the per-server TLS config is not shared
			// between goroutines.
			c := *q.client
			c.TLSConfig = tlsConfig(q.sni)
			client = &c
		}
		conn, err := client.Dial(q.addr)
		if err != nil {
			return nil, err
		}
		q.conn = conn
	}
	resp, _, err := q.client.ExchangeWithConn(msg, q.conn)
	return resp, err
}

// tcpExchange answers a truncated UDP query over TCP with a throwaway
// connection, which is only paid for on the rare truncated answer.
func (q *streamQuerier) tcpExchange(msg *dns.Msg) (*dns.Msg, error) {
	family := FamilyOf(q.server.Address)
	if !family.IsLiteral() {
		family = q.opts.Family
	}
	client := &dns.Client{Net: socketNetwork("tcp", family), Timeout: q.opts.Timeout}
	host := hostOf(q.server.Address)
	resp, _, err := client.Exchange(msg, net.JoinHostPort(resolveHost(host, q.opts.Timeout, family), "53"))
	return resp, err
}

// reset drops the current connection so the next query reconnects.
func (q *streamQuerier) reset() {
	if q.conn != nil {
		_ = q.conn.Close()
		q.conn = nil
	}
}
