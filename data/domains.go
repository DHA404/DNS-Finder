package data

import (
	_ "embed"
	"strings"
)

// The domain lists are plain text, one domain per line; blank lines and lines
// starting with '#' are ignored. They are embedded into the binary so a run
// never depends on a data file being present next to the executable.
//
//go:embed cn_domains.txt
var cnDomainsRaw string

//go:embed intl_domains.txt
var intlDomainsRaw string

// parseDomainList splits a line-oriented list, dropping comments and blanks.
func parseDomainList(raw string) []string {
	var out []string
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// CNDomains returns the built-in 国内 domain list.
func CNDomains() []string { return parseDomainList(cnDomainsRaw) }

// IntlDomains returns the built-in 国外 domain list.
func IntlDomains() []string { return parseDomainList(intlDomainsRaw) }
