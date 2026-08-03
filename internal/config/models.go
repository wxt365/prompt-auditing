package config

import "time"

type Config struct {
	Path                  string        `yaml:"-"`
	Version               int           `yaml:"version"`
	Listen                string        `yaml:"listen"`
	Upstream              string        `yaml:"upstream"`
	PolicyDB              string        `yaml:"policy_db"`
	AuditDB               string        `yaml:"audit_db"`
	MaxBodyBytes          int64         `yaml:"max_body_bytes"`
	MaxConcurrentRequests int           `yaml:"max_concurrent_requests"`
	AuditRetentionDays    int           `yaml:"audit_retention_days"`
	AuditMaxBytes         int64         `yaml:"audit_max_bytes"`
	UpstreamHeaderTimeout time.Duration `yaml:"-"`
	ShutdownTimeout       time.Duration `yaml:"-"`
}

type LimitsConfig struct {
	MaxCompressedBytes   int64
	MaxDecompressedBytes int64
	MaxConcurrent        int
}
