//go:build nodoh3

package model

// doh3Disabled records that this build was compiled without DoH3 support, so
// UnsupportedProtocol can explain the situation instead of letting every DoH3
// server fail at the transport layer. The build tag is mirrored from the
// transport package's switch; see internal/dnsclient/https_nodoh3.go.
const doh3Disabled = true
