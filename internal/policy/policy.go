package policy

import (
	"fmt"
	"os"
	"strings"

	"github.com/V3idt/lattice-cli/internal/model"
	"gopkg.in/yaml.v3"
)

type rawPolicy struct {
	Version  string                       `yaml:"version"`
	Defaults map[string]string            `yaml:"defaults"`
	Rules    map[string]string            `yaml:"rules"`
	Engines  map[string]map[string]string `yaml:"engines"`
}

type Policy struct {
	Version  string
	Defaults map[model.Severity]model.Action
	Rules    map[string]model.Action
	Engines  map[string]map[string]model.Action
}

func Default() Policy {
	return Policy{
		Version: "0.1",
		Defaults: map[model.Severity]model.Action{
			model.SeverityCritical: model.ActionBlock,
			model.SeverityHigh:     model.ActionBlock,
			model.SeverityMedium:   model.ActionWarn,
			model.SeverityLow:      model.ActionWarn,
			model.SeverityInfo:     model.ActionIgnore,
		},
		Rules:   map[string]model.Action{},
		Engines: map[string]map[string]model.Action{},
	}
}

func Load(path string) (Policy, error) {
	if strings.TrimSpace(path) == "" {
		p := Default()
		return p, nil
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		p := Default()
		return p, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}

	var raw rawPolicy
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Policy{}, fmt.Errorf("parse policy yaml: %w", err)
	}

	p := Default()
	if raw.Version != "" {
		p.Version = raw.Version
	}
	for sev, action := range raw.Defaults {
		p.Defaults[model.NormalizeSeverity(sev)] = normalizeAction(action)
	}
	for rule, action := range raw.Rules {
		p.Rules[strings.TrimSpace(rule)] = normalizeAction(action)
	}
	for engine, rules := range raw.Engines {
		trimmedEngine := strings.TrimSpace(engine)
		if trimmedEngine == "" {
			continue
		}
		if _, ok := p.Engines[trimmedEngine]; !ok {
			p.Engines[trimmedEngine] = map[string]model.Action{}
		}
		for rule, action := range rules {
			p.Engines[trimmedEngine][strings.TrimSpace(rule)] = normalizeAction(action)
		}
	}
	return p, nil
}

func normalizeAction(raw string) model.Action {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(model.ActionBlock):
		return model.ActionBlock
	case string(model.ActionIgnore):
		return model.ActionIgnore
	default:
		return model.ActionWarn
	}
}

func (p Policy) ActionForFinding(f model.Finding) model.Action {
	compositeRule := f.Engine + ":" + f.RuleID
	if action, ok := p.Rules[compositeRule]; ok {
		return action
	}
	if action, ok := p.Rules[f.RuleID]; ok {
		return action
	}

	if engineRules, ok := p.Engines[f.Engine]; ok {
		if action, ok := engineRules[f.RuleID]; ok {
			return action
		}
		if action, ok := engineRules["*"]; ok {
			return action
		}
	}

	if action, ok := p.Defaults[f.Severity]; ok {
		return action
	}
	return model.ActionWarn
}
