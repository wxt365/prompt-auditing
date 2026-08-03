package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultBodyLimit = 5 << 20

func Load(path string) (Config, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("解析配置路径: %w", err)
	}
	file, err := os.Open(absolutePath)
	if err != nil {
		return Config{}, fmt.Errorf("打开 Gateway 配置: %w", err)
	}
	defer file.Close()
	var cfg Config
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("解析 Gateway 配置: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, errors.New("Gateway 配置只能包含一个 YAML 文档")
		}
		return Config{}, fmt.Errorf("解析 Gateway 配置尾部: %w", err)
	}
	cfg.Path = absolutePath
	applyDefaults(&cfg)
	resolvePaths(&cfg)
	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8080"
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = defaultBodyLimit
	}
	if cfg.MaxConcurrentRequests == 0 {
		cfg.MaxConcurrentRequests = 10
	}
	if cfg.AuditRetentionDays == 0 {
		cfg.AuditRetentionDays = 30
	}
	if cfg.AuditMaxBytes == 0 {
		cfg.AuditMaxBytes = 100 << 20
	}
	cfg.UpstreamHeaderTimeout = 30 * time.Second
	cfg.ShutdownTimeout = 15 * time.Second
}

func resolvePaths(cfg *Config) {
	directory := filepath.Dir(cfg.Path)
	if cfg.PolicyDB != "" && !filepath.IsAbs(cfg.PolicyDB) {
		cfg.PolicyDB = filepath.Join(directory, cfg.PolicyDB)
	}
	if cfg.AuditDB != "" && !filepath.IsAbs(cfg.AuditDB) {
		cfg.AuditDB = filepath.Join(directory, cfg.AuditDB)
	}
	cfg.PolicyDB = filepath.Clean(cfg.PolicyDB)
	cfg.AuditDB = filepath.Clean(cfg.AuditDB)
}

func validate(cfg Config) error {
	if cfg.Version != 1 {
		return fmt.Errorf("不支持的 Gateway 配置版本 %d", cfg.Version)
	}
	host, portText, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen 必须包含有效地址和端口: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listen 必须使用回环地址")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("listen 端口必须在 1 到 65535 之间")
	}
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil || upstream.Scheme != "https" || upstream.Host == "" {
		return errors.New("upstream 必须是固定的 HTTPS URL")
	}
	if upstream.RawQuery != "" || upstream.Fragment != "" || upstream.User != nil {
		return errors.New("upstream 不得包含用户信息、查询参数或片段")
	}
	if cfg.PolicyDB == "." || cfg.AuditDB == "." || cfg.PolicyDB == "" || cfg.AuditDB == "" {
		return errors.New("policy_db 和 audit_db 不能为空")
	}
	if sameDatabaseFile(cfg.PolicyDB, cfg.AuditDB) {
		return errors.New("policy_db 和 audit_db 必须使用不同文件")
	}
	if cfg.MaxBodyBytes <= 0 || cfg.MaxConcurrentRequests <= 0 || cfg.AuditRetentionDays <= 0 || cfg.AuditMaxBytes <= 0 {
		return errors.New("请求限制与审计保留参数必须大于零")
	}
	return nil
}

func sameDatabaseFile(first, second string) bool {
	if first == second {
		return true
	}
	firstInfo, firstErr := os.Stat(first)
	secondInfo, secondErr := os.Stat(second)
	return firstErr == nil && secondErr == nil && os.SameFile(firstInfo, secondInfo)
}
