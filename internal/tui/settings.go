package tui

import (
	"strings"
	"time"

	"dns-opti/internal/config"
	"dns-opti/internal/model"
	"dns-opti/internal/settings"
)

// settingsFrom captures the current configuration as a persistable value.
//
// Only the options the menu actually edits are recorded. Deriving the struct
// from m.cfg rather than from the individual widgets means the file always
// reflects what a run would really use, including the advanced screen's values
// once syncAdvanced has copied them across.
func (m *Model) settingsFrom() settings.Settings {
	categories := make([]string, 0, len(m.cfg.ServerCategories))
	categories = append(categories, m.cfg.ServerCategories...)

	protocols := make([]string, 0, len(m.cfg.Protocols))
	for _, p := range m.cfg.Protocols {
		protocols = append(protocols, string(p))
	}

	policies := make([]string, 0, len(m.cfg.Policies))
	for _, k := range m.cfg.Policies {
		policies = append(policies, string(k))
	}

	systemDNS := m.cfg.SystemDNS
	return settings.Settings{
		Domains:      m.cfg.Domains,
		Protocols:    protocols,
		Combo:        m.cfg.Combo,
		Regions:      append([]string(nil), m.cfg.Regions...),
		Policies:     policies,
		ServerClass:  strings.Join(categories, ","),
		IPVersion:    string(m.cfg.IPVersion),
		TimeoutMS:    int(m.adv.timeout / time.Millisecond),
		Attempts:     m.adv.attempts,
		Concurrency:  m.adv.concurrency,
		SystemDNS:    &systemDNS,
		Formula:      string(m.formula),
		WarmupDomain: m.adv.warmup,
	}
}

// applySettings folds a persisted configuration into the menu state.
//
// Every value is validated before it is adopted, and an unparsable one is
// skipped in favour of the built-in default. A hand-edited or truncated
// settings file must not be able to leave the menu holding a configuration it
// cannot run — the user would then have to delete the file to recover, which is
// exactly the kind of trap a preference file should never set.
func (m *Model) applySettings(s settings.Settings) {
	if s.Domains != "" {
		m.cfg.Domains = s.Domains
	}
	if len(s.Protocols) > 0 {
		if protocols, err := config.ParseProtocols(strings.Join(s.Protocols, ",")); err == nil {
			m.cfg.Protocols = protocols
			m.cfg.Combo = ""
			// A persisted combo is only restored when it still agrees with the
			// protocol list, so the pair can never come back inconsistent.
			if s.Combo != "" {
				if expanded, ok := model.ComboProtocols(s.Combo); ok && sameProtocols(expanded, protocols) {
					m.cfg.Combo = s.Combo
				}
			}
		}
	}
	if len(s.Regions) > 0 {
		// Regions are canonicalised rather than validated against a country
		// list, matching how the CLI treats them.
		m.cfg.Regions = cleanRegions(s.Regions)
	}
	if len(s.Policies) > 0 {
		if kinds, err := config.ParsePolicies(strings.Join(s.Policies, ",")); err == nil {
			m.cfg.Policies = kinds
		}
	}
	if s.ServerClass != "" {
		if categories, err := config.ParseServerCategories(s.ServerClass); err == nil {
			m.cfg.ServerCategories = categories
		}
	}
	if s.IPVersion != "" {
		if v, err := config.ParseIPVersion(s.IPVersion); err == nil {
			m.cfg.IPVersion = v
		}
	}
	if s.TimeoutMS > 0 {
		m.adv.timeout = time.Duration(s.TimeoutMS) * time.Millisecond
	}
	if s.Attempts > 0 {
		m.adv.attempts = s.Attempts
	}
	if s.Concurrency >= 0 {
		m.adv.concurrency = s.Concurrency
	}
	if s.SystemDNS != nil {
		m.cfg.SystemDNS = *s.SystemDNS
	}
	if s.Formula != "" {
		if f, err := config.ParseFormula(s.Formula); err == nil {
			m.formula = f
		}
	}
	if s.WarmupDomain != "" {
		m.adv.warmup = s.WarmupDomain
	}
	m.cfg.Formula = string(m.formula)
}

// cleanRegions canonicalises a persisted region list, dropping empties.
func cleanRegions(regions []string) []string {
	out := make([]string, 0, len(regions))
	for _, r := range regions {
		if trimmed := strings.TrimSpace(r); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// persist writes the current configuration to the settings file.
//
// It is best effort by design: a read-only install directory must not stop the
// user from running a test. The failure is surfaced on the status line rather
// than raised, because losing a preference is an inconvenience, not a reason to
// abandon a benchmark.
func (m *Model) persist() {
	if m.deps.SettingsPath == "" {
		return
	}
	if err := settings.SaveTo(m.deps.SettingsPath, m.settingsFrom()); err != nil {
		m.statusMsg = "设置未能保存: " + err.Error()
		m.statusErr = true
		return
	}
	m.settingsSaved = true
}

// loadSettings reads the settings file into the menu state at startup.
func (m *Model) loadSettings() {
	if m.deps.SettingsPath == "" {
		return
	}
	s, ok, err := settings.LoadFrom(m.deps.SettingsPath)
	if err != nil {
		// A corrupt file is reported but never fatal: the menu continues on its
		// defaults and the next change overwrites the broken file.
		m.statusMsg = "设置文件无法读取，已使用默认值: " + err.Error()
		m.statusErr = true
		return
	}
	if !ok {
		return
	}
	m.applySettings(s)
	m.settingsLoaded = true
}
