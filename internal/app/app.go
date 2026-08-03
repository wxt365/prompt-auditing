package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/gateway"
	"github.com/xiaotaowang/prompt-auditing/internal/platform"
	"github.com/xiaotaowang/prompt-auditing/internal/security"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

type BuildInfo struct {
	Version string
	Commit  string
}

type runner struct {
	stdout io.Writer
	stderr io.Writer
	build  BuildInfo
}

func Run(args []string, stdout, stderr io.Writer, build BuildInfo) int {
	instance := runner{stdout: stdout, stderr: stderr, build: build}
	if err := instance.run(args); err != nil {
		fmt.Fprintln(stderr, "错误:", err)
		return 1
	}
	return 0
}

func (r runner) run(args []string) error {
	if len(args) == 0 {
		r.usage()
		return errors.New("缺少命令")
	}
	switch args[0] {
	case "init":
		return r.init(args[1:])
	case "check-config":
		return r.checkConfig(args[1:])
	case "start":
		return r.start(args[1:])
	case "policy":
		return r.policy(args[1:])
	case "version":
		fmt.Fprintf(r.stdout, "codex-gateway %s (%s)\n", r.build.Version, r.build.Commit)
		return nil
	case "help", "-h", "--help":
		r.usage()
		return nil
	default:
		r.usage()
		return fmt.Errorf("未知命令 %s", args[0])
	}
}

func (r runner) usage() {
	fmt.Fprintln(r.stdout, `用法: codex-gateway <命令> [参数]

命令:
  init          创建 policy.db、audit.db 和初始 Schema
  check-config  校验启动配置、数据库和规则
  start         启动本地安全网关
  policy        管理本地安全规则
  version       显示版本信息`)
}

func (r runner) init(args []string) error {
	path, err := parseConfigFlag("init", args, r.stderr)
	if err != nil {
		return err
	}
	if err := validateConfigLocation(path); err != nil {
		return err
	}
	if err := platform.SecureFile(path); err != nil {
		return fmt.Errorf("保护 Gateway 配置文件: %w", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := storage.InitDatabases(ctx, cfg.PolicyDB, cfg.AuditDB); err != nil {
		return err
	}
	fmt.Fprintf(r.stdout, "初始化完成\npolicy_db=%s\naudit_db=%s\n", cfg.PolicyDB, cfg.AuditDB)
	return nil
}

func (r runner) checkConfig(args []string) error {
	path, err := parseConfigFlag("check-config", args, r.stderr)
	if err != nil {
		return err
	}
	cfg, err := loadProtectedConfig(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	policyStore, err := storage.OpenPolicy(ctx, cfg.PolicyDB)
	if err != nil {
		return err
	}
	rules, err := policyStore.Load(ctx)
	closeErr := policyStore.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if _, err := security.NewEngine(rules); err != nil {
		return err
	}
	if err := storage.CheckAudit(ctx, cfg.AuditDB); err != nil {
		return err
	}
	fmt.Fprintf(r.stdout, "配置有效，规则版本=%s，规则数量=%d\n", rules.Version, len(rules.Rules))
	return nil
}

func (r runner) start(args []string) error {
	path, err := parseConfigFlag("start", args, r.stderr)
	if err != nil {
		return err
	}
	cfg, err := loadProtectedConfig(path)
	if err != nil {
		return err
	}
	localToken := os.Getenv("CODEX_GATEWAY_TOKEN")
	if len(localToken) < 32 {
		return errors.New("CODEX_GATEWAY_TOKEN 必须至少包含 32 个字节")
	}
	upstreamKey := os.Getenv("OPENAI_API_KEY")
	if upstreamKey == "" {
		return errors.New("必须设置 OPENAI_API_KEY")
	}
	ctx := context.Background()
	policyStore, err := storage.OpenPolicy(ctx, cfg.PolicyDB)
	if err != nil {
		return err
	}
	rules, err := policyStore.Load(ctx)
	closeErr := policyStore.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	engine, err := security.NewEngine(rules)
	if err != nil {
		return err
	}
	auditStore, err := storage.OpenAudit(ctx, cfg.AuditDB, cfg.AuditRetentionDays, cfg.AuditMaxBytes)
	if err != nil {
		return err
	}
	defer auditStore.Close()
	maintenanceCtx, stopMaintenance := context.WithCancel(context.Background())
	maintenanceDone := make(chan struct{})
	go func() {
		defer close(maintenanceDone)
		auditStore.RunMaintenance(maintenanceCtx, time.Hour)
	}()
	defer func() {
		stopMaintenance()
		<-maintenanceDone
	}()

	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return err
	}
	client, err := newUpstreamHTTPClient(cfg.UpstreamHeaderTimeout)
	if err != nil {
		return err
	}
	handler, err := gateway.NewHandler(gateway.Options{
		Upstream: upstream, Client: client, Engine: engine, Audit: auditStore,
		LocalToken: localToken, UpstreamKey: upstreamKey,
		Limits: config.LimitsConfig{
			MaxCompressedBytes: cfg.MaxBodyBytes, MaxDecompressedBytes: cfg.MaxBodyBytes,
			MaxConcurrent: cfg.MaxConcurrentRequests,
		},
	})
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: cfg.Listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20,
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("监听 Gateway 地址 %s: %w", cfg.Listen, err)
	}
	serverErrors := make(chan error, 1)
	go func() {
		fmt.Fprintf(r.stdout, "Gateway 已启动 listen=%s upstream=%s rule_version=%s policy_db=%s audit_db=%s\n",
			cfg.Listen, upstream.Host, engine.RuleSetVersion(), cfg.PolicyDB, cfg.AuditDB)
		serverErrors <- server.Serve(listener)
	}()

	shutdownContext, stopSignal := signal.NotifyContext(context.Background(), platform.ShutdownSignals()...)
	defer stopSignal()
	select {
	case serverErr := <-serverErrors:
		if !errors.Is(serverErr, http.ErrServerClosed) {
			return serverErr
		}
		return nil
	case <-shutdownContext.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("优雅停止失败: %w", err)
		}
		stopMaintenance()
		<-maintenanceDone
		fmt.Fprintln(r.stdout, "Gateway 已停止")
		return nil
	}
}

func newUpstreamHTTPClient(headerTimeout time.Duration) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if certificatePath := os.Getenv("SSL_CERT_FILE"); certificatePath != "" {
		certificatePEM, err := os.ReadFile(certificatePath)
		if err != nil {
			return nil, fmt.Errorf("读取 SSL_CERT_FILE: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(certificatePEM) {
			return nil, errors.New("SSL_CERT_FILE 不包含有效 PEM 证书")
		}
		tlsConfig.RootCAs = roots
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	transport.DisableCompression = true
	transport.ResponseHeaderTimeout = headerTimeout
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Transport: transport}, nil
}

func (r runner) policy(args []string) error {
	if len(args) == 0 {
		return errors.New("policy 缺少子命令")
	}
	subcommand := args[0]
	flags := flag.NewFlagSet("policy "+subcommand, flag.ContinueOnError)
	flags.SetOutput(r.stderr)
	configPath := flags.String("config", "config/gateway.yaml", "Gateway 配置路径")
	id := flags.String("id", "", "规则 ID")
	caseSensitive := flags.Bool("case-sensitive", false, "区分大小写")
	action := flags.String("action", "block", "规则动作")
	pattern := flags.String("pattern", "", "正则表达式")
	replacement := flags.String("replacement", "", "正则替换值")
	var keywords stringList
	var mappings stringList
	flags.Var(&keywords, "keyword", "关键字，可重复")
	flags.Var(&mappings, "mapping", "source=target，可重复")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("不支持的位置参数: %s", strings.Join(flags.Args(), " "))
	}
	cfg, err := loadProtectedConfig(*configPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := storage.OpenPolicy(ctx, cfg.PolicyDB)
	if err != nil {
		return err
	}
	defer store.Close()

	switch subcommand {
	case "list":
		set, err := store.Load(ctx)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(r.stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(set)
	case "add-block":
		err = store.AddBlock(ctx, *id, keywords, *caseSensitive)
	case "add-replacement":
		var parsed []storage.Mapping
		parsed, err = parseMappings(mappings)
		if err == nil {
			err = store.AddReplacement(ctx, *id, parsed, *caseSensitive)
		}
	case "add-regex":
		err = store.AddRegex(ctx, *id, *action, *pattern, *replacement, *caseSensitive)
	case "add-private-ipv4":
		err = store.AddPrivateIPv4(ctx, *id, *action)
	case "enable":
		err = store.SetEnabled(ctx, *id, true)
	case "disable":
		err = store.SetEnabled(ctx, *id, false)
	case "delete":
		err = store.Delete(ctx, *id)
	default:
		return fmt.Errorf("未知 policy 子命令 %s", subcommand)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(r.stdout, "规则操作完成: %s\n", subcommand)
	return nil
}

func loadProtectedConfig(path string) (config.Config, error) {
	if err := validateConfigLocation(path); err != nil {
		return config.Config{}, err
	}
	if err := platform.ValidateSecureFile(path); err != nil {
		return config.Config{}, fmt.Errorf("Gateway 配置文件权限校验失败: %w", err)
	}
	return config.Load(path)
}

func validateConfigLocation(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("解析 Gateway 配置路径: %w", err)
	}
	locations := []string{absolute}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return fmt.Errorf("解析 Gateway 配置真实路径: %w", err)
	}
	if resolved != absolute {
		locations = append(locations, resolved)
	}
	for _, location := range locations {
		if err := platform.ValidateTrustedDir(filepath.Dir(location)); err != nil {
			return fmt.Errorf("Gateway 配置目录不可信: %w", err)
		}
	}
	return nil
}

func parseConfigFlag(command string, args []string, stderr io.Writer) (string, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "config/gateway.yaml", "Gateway 配置路径")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if flags.NArg() != 0 {
		return "", fmt.Errorf("不支持的位置参数: %s", strings.Join(flags.Args(), " "))
	}
	return *path, nil
}

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func parseMappings(values []string) ([]storage.Mapping, error) {
	result := make([]storage.Mapping, 0, len(values))
	for _, value := range values {
		parts := strings.SplitN(value, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] == "" {
			return nil, fmt.Errorf("替换映射格式无效: %s", value)
		}
		result = append(result, storage.Mapping{Source: parts[0], Target: parts[1]})
	}
	return result, nil
}
