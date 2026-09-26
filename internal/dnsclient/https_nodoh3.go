//go:build nodoh3

package dnsclient

import (
	"fmt"
	"net/http"

	"dns-opti/internal/model"
)

// newHTTPTransport builds the HTTP transport for the given protocol. This
// build was compiled with the "nodoh3" tag, which drops the QUIC dependency
// (see PLAN 十三: DoH3 is disabled when the library does not build on a
// platform).
func newHTTPTransport(protocol model.Protocol, host string, family model.IPVersion, opts Options) (http.RoundTripper, func() error, error) {
	if protocol == model.ProtocolDoH3 {
		return nil, nil, fmt.Errorf("本次构建未启用 DoH3（构建标签 nodoh3）")
	}
	return newHTTPS2Transport(host, family, opts)
}
