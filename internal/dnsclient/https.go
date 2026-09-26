package dnsclient

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/miekg/dns"

	"dns-opti/internal/model"
)

// maxDoHBody bounds how much of a DoH response body is read. DNS answers are
// far smaller than this; the bound only protects against a misbehaving server.
const maxDoHBody = 64 * 1024

// httpsQuerier queries a server over DoH or DoH3. Both carry the same RFC 8484
// wire-format message; only the HTTP transport differs.
//
// The endpoint hostname is resolved to a literal address up front so that the
// system resolver is not consulted (and not measured) on every query, while
// the original hostname is preserved for the TLS SNI and certificate check.
type httpsQuerier struct {
	server model.Server
	opts   Options
	host   string // hostname used for SNI / certificate verification
	url    string // request URL, with the literal address substituted in
	client *http.Client
	close  func() error
}

// newHTTPSQuerier builds a querier for DoH and DoH3.
func newHTTPSQuerier(server model.Server, opts Options) (*httpsQuerier, error) {
	u, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("无效的 DoH 地址 %q: %w", server.Address, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("DoH 地址必须以 https:// 开头: %q", server.Address)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("DoH 地址缺少主机名: %q", server.Address)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}

	q := &httpsQuerier{server: server, opts: opts, host: host}

	// A literal endpoint keeps its own family; a hostname follows the option.
	family := FamilyOf(server.Address)
	if !family.IsLiteral() {
		family = opts.Family
	}
	if _, err := netip.ParseAddr(host); err != nil {
		// The endpoint is a hostname: dial the resolved literal directly and
		// keep the original name for SNI and the certificate check.
		resolved := resolveHost(host, opts.Timeout, family)
		if resolved != host {
			u.Host = net.JoinHostPort(resolved, port)
		}
	}
	q.url = u.String()

	transport, closeFn, err := newHTTPTransport(server.Protocol, host, family, opts)
	if err != nil {
		return nil, err
	}
	q.client = &http.Client{Timeout: opts.Timeout, Transport: transport}
	q.close = closeFn
	return q, nil
}

// Query sends one A query over the HTTP transport and reports the round trip.
func (q *httpsQuerier) Query(domain string) (time.Duration, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	wire, err := msg.Pack()
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequest(http.MethodPost, q.url, bytes.NewReader(wire))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	// The Host header must keep the original name when the URL dials an IP.
	req.Host = q.host

	start := time.Now()
	resp, err := q.client.Do(req)
	if err != nil {
		return time.Since(start), err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDoHBody)) // drain so the connection can be reused
		return time.Since(start), fmt.Errorf("HTTP 状态码 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHBody))
	elapsed := time.Since(start)
	if err != nil {
		return elapsed, err
	}

	var reply dns.Msg
	if err := reply.Unpack(body); err != nil {
		return elapsed, fmt.Errorf("解析 DoH 响应失败: %w", err)
	}
	if reply.Rcode != dns.RcodeSuccess {
		return elapsed, fmt.Errorf("DNS 响应码 %s", dns.RcodeToString[reply.Rcode])
	}
	return elapsed, nil
}

// Warmup primes the connection with the configured warm-up domain.
func (q *httpsQuerier) Warmup() error {
	_, err := q.Query(warmupName(q.opts))
	return err
}

// Lookup returns the raw outcome of one A query over the HTTP transport.
//
// A non-200 status is reported as an error because it means the DoH endpoint
// itself refused the request, which says nothing about the queried name; the
// detection must not read that as a policy answer.
func (q *httpsQuerier) Lookup(domain string) (LookupResult, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	wire, err := msg.Pack()
	if err != nil {
		return LookupResult{}, err
	}

	req, err := http.NewRequest(http.MethodPost, q.url, bytes.NewReader(wire))
	if err != nil {
		return LookupResult{}, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Host = q.host

	resp, err := q.client.Do(req)
	if err != nil {
		return LookupResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDoHBody))
		return LookupResult{}, fmt.Errorf("HTTP 状态码 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHBody))
	if err != nil {
		return LookupResult{}, err
	}

	var reply dns.Msg
	if err := reply.Unpack(body); err != nil {
		return LookupResult{}, fmt.Errorf("解析 DoH 响应失败: %w", err)
	}
	return resultFromMsg(&reply), nil
}

// Family reports the address family actually dialled: the endpoint's own family
// for a literal, or the family the hostname resolved to (which the request URL
// now carries as a literal address).
func (q *httpsQuerier) Family() model.IPVersion {
	if u, err := url.Parse(q.url); err == nil {
		if f := FamilyOf(u.Hostname()); f.IsLiteral() {
			return f
		}
	}
	return FamilyOf(q.server.Address)
}

// ResolvedIP reports the literal address the request is sent to. The URL was
// rewritten to the resolved address by newHTTPSQuerier, so its host is the
// address of record; a bare IP endpoint keeps its own address.
func (q *httpsQuerier) ResolvedIP() string {
	if u, err := url.Parse(q.url); err == nil {
		if host := u.Hostname(); host != "" {
			if _, perr := netip.ParseAddr(host); perr == nil {
				return host
			}
		}
	}
	return literalOrEmpty(q.server.Address)
}

// Close releases the transport, which also closes idle and active connections.
func (q *httpsQuerier) Close() error {
	if q.close != nil {
		return q.close()
	}
	return nil
}

// newHTTPS2Transport builds the keep-alive HTTP/1.1 + HTTP/2 transport used by
// DoH. The transport is per server, so connections are never shared between
// servers being compared. The dialer is pinned to the requested address family
// so a dual-stack host cannot silently connect over the other one.
func newHTTPS2Transport(host string, family model.IPVersion, opts Options) (*http.Transport, func() error, error) {
	dialer := dialerFor(opts.Timeout)
	t := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialContextForFamily(dialer, family),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   opts.Timeout,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: opts.Timeout,
		TLSClientConfig:       tlsConfig(host),
	}
	return t, func() error { t.CloseIdleConnections(); return nil }, nil
}
