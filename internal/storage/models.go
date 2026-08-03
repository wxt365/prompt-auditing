package storage

type Mapping struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

type Rule struct {
	ID            string    `json:"id"`
	Type          string    `json:"type"`
	Action        string    `json:"action"`
	Enabled       bool      `json:"enabled"`
	CaseSensitive bool      `json:"case_sensitive"`
	Pattern       string    `json:"pattern,omitempty"`
	Replacement   string    `json:"replacement,omitempty"`
	Keywords      []string  `json:"keywords,omitempty"`
	Mappings      []Mapping `json:"mappings,omitempty"`
}

type RuleSet struct {
	Version       string `json:"version"`
	DefaultAction string `json:"default_action"`
	Rules         []Rule `json:"rules"`
}
