package dnsclient

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"dns-opti/internal/model"
)

// dialerFor returns a net.Dialer bounded by the query timeout.
func dialerFor(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
}

// dialContextFunc matches net.Dialer.DialContext.
type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// dialContextForFamily pins dialling to one address family, so a dual-stack
// host cannot silently connect over the family the user did not ask for.
//
// net.Dialer has no field to express this: the family is part of the network
// argument of each Dial call, which http.Transport supplies as "tcp". The
// network is therefore rewritten on the way through. An empty family leaves the
// call untouched, so the kernel follows the system's own preference.
func dialContextForFamily(d *net.Dialer, family model.IPVersion) dialContextFunc {
	if !family.IsLiteral() {
		return d.DialContext
	}
	suffix := "4"
	if family == model.IPv6 {
		suffix = "6"
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return d.DialContext(ctx, network+suffix, address)
	}
}

// tlsConfig builds the TLS client configuration for the given server name.
// Verification is left enabled: an encrypted transport that cannot be verified
// is not a transport a user should switch to.
func tlsConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"dot"},
	}
}
