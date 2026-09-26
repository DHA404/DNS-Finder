//go:build !nodoh3

package dnsclient

import (
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"dns-opti/internal/model"
)

// newHTTPTransport builds the HTTP transport for the given protocol. DoH3 is
// carried over QUIC; the endpoint is a regular https:// URL and the
// wire-format query is identical to DoH. The family pins the connection to one
// address family when the run asked for one.
func newHTTPTransport(protocol model.Protocol, host string, family model.IPVersion, opts Options) (http.RoundTripper, func() error, error) {
	if protocol != model.ProtocolDoH3 {
		return newHTTPS2Transport(host, family, opts)
	}

	rt := &http3.Transport{
		TLSClientConfig: tlsConfig(host),
		QUICConfig:      quicConfig(opts),
	}
	// http3.Transport implements Close (not CloseIdleConnections).
	return rt, rt.Close, nil
}

// quicConfig bounds the QUIC handshake and idle behaviour of a DoH3
// connection. MaxIdleTimeout is kept generous so the connection survives the
// whole run and every measured query reuses it.
func quicConfig(opts Options) *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: opts.Timeout,
		MaxIdleTimeout:       90 * time.Second,
		KeepAlivePeriod:      20 * time.Second,
	}
}
