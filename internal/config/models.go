package config

import (
	"errors"
	"time"

	"gopkg.in/yaml.v3"
)

type HeaderTimeoutSeconds int64

func (s *HeaderTimeoutSeconds) UnmarshalYAML(node *yaml.Node) error {
	// YAML 默认会将小数截断为整数，秒数配置必须明确拒绝这种隐式转换。
	if node.Tag != "!!int" {
		return errors.New("upstream_header_timeout_seconds 必须是整数秒数")
	}
	var value int64
	if err := node.Decode(&value); err != nil {
		return err
	}
	*s = HeaderTimeoutSeconds(value)
	return nil
}

type Config struct {
	Path                         string               `yaml:"-"`
	Version                      int                  `yaml:"version"`
	Listen                       string               `yaml:"listen"`
	Upstream                     string               `yaml:"upstream"`
	PolicyDB                     string               `yaml:"policy_db"`
	AuditDB                      string               `yaml:"audit_db"`
	MaxBodyBytes                 int64                `yaml:"max_body_bytes"`
	MaxConcurrentRequests        int                  `yaml:"max_concurrent_requests"`
	UpstreamHeaderTimeoutSeconds HeaderTimeoutSeconds `yaml:"upstream_header_timeout_seconds"`
	AuditRetentionDays           int                  `yaml:"audit_retention_days"`
	AuditMaxBytes                int64                `yaml:"audit_max_bytes"`
	UpstreamHeaderTimeout        time.Duration        `yaml:"-"`
	ShutdownTimeout              time.Duration        `yaml:"-"`
}

type LimitsConfig struct {
	MaxCompressedBytes   int64
	MaxDecompressedBytes int64
	MaxConcurrent        int
}
