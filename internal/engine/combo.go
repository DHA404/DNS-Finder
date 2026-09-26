package engine

import (
	"cmp"
	"fmt"
	"slices"

	"dns-opti/internal/model"
)

// TransportComparison is one provider's two transports measured in a combined
// "UDP + DoH" run, side by side.
type TransportComparison struct {
	// Combo is the shared provider identifier of the pairing.
	Combo string `json:"combo"`
	// Name is the display name of the provider.
	Name string `json:"name"`
	// Region is the provider's region code.
	Region string `json:"region"`
	// UDP and DoH are the two measurements. Either may be nil when the
	// provider only publishes that transport, in which case the comparison is
	// reported but no delta can be computed.
	UDP *TransportSide `json:"udp,omitempty"`
	DoH *TransportSide `json:"doh,omitempty"`
	// AvgDeltaMS is DoH's average latency minus UDP's, in milliseconds. It is
	// positive when DoH is slower — the usual case, because DoH pays for TLS
	// and HTTP on top of the query. It is zero when one side is missing.
	AvgDeltaMS float64 `json:"avg_delta_ms"`
	// RateDelta is DoH's success rate minus UDP's. Negative means the
	// encrypted transport is less reliable here.
	RateDelta float64 `json:"rate_delta"`
	// P95DeltaMS is DoH's P95 minus UDP's.
	P95DeltaMS float64 `json:"p95_delta_ms"`
	// Comparable reports whether both sides have at least one success, which is
	// what makes the deltas meaningful.
	Comparable bool `json:"comparable"`
}

// TransportSide is one transport's aggregate for a provider inside a comparison.
//
// A provider commonly publishes several addresses for one transport (AliDNS
// has two UDP resolvers but a single DoH endpoint), so a side may cover more
// than one endpoint. Addresses records exactly which endpoints were folded
// together, and Endpoints their count, so an aggregated side is never mistaken
// for a single server.
type TransportSide struct {
	// Addresses are the endpoints aggregated into this side, in first-seen
	// order. The first is the representative address.
	Addresses []string `json:"addresses"`
	// Name is the display name of the side's first endpoint.
	Name string `json:"name,omitempty"`
	// Protocol is the transport this side measures.
	Protocol model.Protocol `json:"protocol"`
	// Region is the provider's region code.
	Region string `json:"region,omitempty"`
	// Family is the address family, when the side holds a single endpoint.
	Family model.IPVersion `json:"family,omitempty"`
	// Endpoints is how many addresses were aggregated into this side.
	Endpoints   int     `json:"endpoints"`
	Total       int     `json:"total"`
	Success     int     `json:"success"`
	SuccessRate float64 `json:"success_rate"`
	AvgMS       float64 `json:"avg_ms"`
	P95MS       float64 `json:"p95_ms"`
	StdDevMS    float64 `json:"stddev_ms"`
	// Groups holds the per-domain-group breakdown, which is where the two
	// transports most often differ (a resolver is rarely equally good for
	// domestic and foreign names).
	Groups map[string]Section `json:"groups,omitempty"`
}

// DNS returns the representative endpoint of the side (the first one).
func (t *TransportSide) DNS() string {
	if t == nil || len(t.Addresses) == 0 {
		return ""
	}
	return t.Addresses[0]
}

// Label renders the side's address for a table cell: the address alone for a
// single endpoint, or "address 等 N 个" when several were aggregated.
func (t *TransportSide) Label() string {
	if t == nil || len(t.Addresses) == 0 {
		return ""
	}
	if len(t.Addresses) == 1 {
		return t.Addresses[0]
	}
	return fmt.Sprintf("%s 等 %d 个", t.Addresses[0], len(t.Addresses))
}

// Section is one (transport, domain group) aggregate inside a comparison side.
type Section struct {
	Total       int     `json:"total"`
	Success     int     `json:"success"`
	SuccessRate float64 `json:"success_rate"`
	AvgMS       float64 `json:"avg_ms"`
	P95MS       float64 `json:"p95_ms"`
	StdDevMS    float64 `json:"stddev_ms"`
}

// CompareTransports folds the summary rows of a combined "UDP + DoH" run into
// one comparison entry per provider.
//
// The two transports of a provider are never averaged into a single number: a
// UDP query and a DoH query measure genuinely different things (one round trip
// versus a round trip plus a TLS/HTTP exchange), and merging them would hide
// exactly the difference this mode exists to show. Each provider therefore
// keeps both sides, plus the deltas between them.
//
// Per-domain-group rows are kept on each side so the viewer can show whether a
// transport is faster for domestic or for foreign names — they commonly differ.
func CompareTransports(summaries []model.Summary) []TransportComparison {
	type bucket struct {
		name string
		side map[model.Protocol]*TransportSide
	}
	groups := map[string]*bucket{}
	var order []string

	for _, s := range summaries {
		if s.Combo == "" {
			continue
		}
		if s.Protocol != model.ProtocolUDP && s.Protocol != model.ProtocolDoH {
			continue
		}
		b, ok := groups[s.Combo]
		if !ok {
			b = &bucket{name: s.Name, side: map[model.Protocol]*TransportSide{}}
			groups[s.Combo] = b
			order = append(order, s.Combo)
		}
		if b.name == "" || b.name == s.DNS {
			b.name = s.Name
		}

		side, ok := b.side[s.Protocol]
		if !ok {
			side = &TransportSide{
				Name:     s.Name,
				Protocol: s.Protocol,
				Region:   s.Region,
				Family:   s.Family,
				Groups:   map[string]Section{},
			}
			b.side[s.Protocol] = side
		}
		// Record every distinct endpoint folded into this side, so an aggregate
		// of two resolvers is not presented as a single server.
		if !slices.Contains(side.Addresses, s.DNS) {
			side.Addresses = append(side.Addresses, s.DNS)
		}
		side.Endpoints = len(side.Addresses)
		// The family is only meaningful when the side is one endpoint.
		if len(side.Addresses) > 1 {
			side.Family = model.IPAny
		}
		// Aggregate across the domain groups: totals add up and the averages
		// are weighted by the number of successful queries, so a group with
		// more measurements contributes proportionally.
		side.Groups[s.Group] = Section{
			Total:       s.Total,
			Success:     s.Success,
			SuccessRate: s.SuccessRate,
			AvgMS:       s.AvgMS,
			P95MS:       s.P95MS,
			StdDevMS:    s.StdDevMS,
		}
		side.Total += s.Total
		side.Success += s.Success
		side.AvgMS += s.AvgMS * float64(s.Success)
		side.P95MS += s.P95MS * float64(s.Success)
		side.StdDevMS += s.StdDevMS * float64(s.Success)
	}

	out := make([]TransportComparison, 0, len(order))
	for _, key := range order {
		b := groups[key]
		c := TransportComparison{Combo: key, Name: b.name}

		for _, side := range b.side {
			finishSide(side)
			if c.Region == "" {
				c.Region = side.Region
			}
		}
		c.UDP = b.side[model.ProtocolUDP]
		c.DoH = b.side[model.ProtocolDoH]

		if c.UDP != nil && c.DoH != nil {
			// A delta is only meaningful when both transports answered at least
			// once. Computing one anyway would be actively misleading: a side
			// that never answered has zero latency, so the difference would
			// read as "the encrypted transport is N ms faster" when in fact it
			// never worked at all.
			c.Comparable = c.UDP.Success > 0 && c.DoH.Success > 0
			if c.Comparable {
				c.AvgDeltaMS = c.DoH.AvgMS - c.UDP.AvgMS
				c.P95DeltaMS = c.DoH.P95MS - c.UDP.P95MS
				c.RateDelta = c.DoH.SuccessRate - c.UDP.SuccessRate
			}
		}
		out = append(out, c)
	}

	// Present the pairings with both sides available first (those are the ones
	// the comparison is actually about), then by name for stability.
	slices.SortStableFunc(out, func(a, b TransportComparison) int {
		if a.Comparable != b.Comparable {
			if a.Comparable {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(a.Region, b.Region); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return out
}

// finishSide converts the accumulated weighted sums into averages.
func finishSide(side *TransportSide) {
	if side.Success > 0 {
		n := float64(side.Success)
		side.AvgMS /= n
		side.P95MS /= n
		side.StdDevMS /= n
	} else {
		// No successful query: the latency fields carry no information and must
		// not be presented as a measurement of zero milliseconds.
		side.AvgMS, side.P95MS, side.StdDevMS = 0, 0, 0
	}
	if side.Total > 0 {
		side.SuccessRate = float64(side.Success) / float64(side.Total)
	}
}
