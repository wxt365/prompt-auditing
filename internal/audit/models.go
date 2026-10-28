package audit

import "encoding/json"

type Event struct {
	SchemaVersion   int             `json:"schema_version"`
	EventType       string          `json:"event_type"`
	RequestID       string          `json:"request_id"`
	OccurredAt      string          `json:"occurred_at"`
	User            string          `json:"user"`
	RuleSetVersion  string          `json:"rule_set_version,omitempty"`
	RuleIDs         []string        `json:"rule_ids,omitempty"`
	Categories      []string        `json:"categories,omitempty"`
	MatchedKeywords []string        `json:"matched_keywords,omitempty"`
	MatchCount      int             `json:"match_count"`
	Action          string          `json:"action"`
	Result          string          `json:"result"`
	RequestBody     json.RawMessage `json:"request_body,omitempty"`
	RequestHMAC     string          `json:"request_hmac_sha256,omitempty"`
	UpstreamStatus  *int            `json:"upstream_status"`
	DurationMS      int64           `json:"duration_ms"`
	ErrorCode       string          `json:"error_code,omitempty"`
	Matches         []Match         `json:"-"`
}

type Match struct {
	Action         string
	Reason         string
	RuleID         string
	RuleName       string
	Category       string
	MatchedKeyword string
}
