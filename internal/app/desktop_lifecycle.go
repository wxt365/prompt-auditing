package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/gateway"
	"github.com/xiaotaowang/prompt-auditing/internal/security"
	"github.com/xiaotaowang/prompt-auditing/internal/settings"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

type desktopGateway struct {
	server          *http.Server
	audit           *storage.AuditStore
	transport       *http.Transport
	cancel          context.CancelFunc
	maintenanceDone chan struct{}
	serveDone       chan struct{}
	running         atomic.Bool
	payloadError    *atomic.Value
	requests        sync.WaitGroup
	requestMu       sync.Mutex
	stopping        bool
	version         string
}

type desktopController struct {
	// operationMu 串行化保存与启停；mu 只保护内存快照，二者不反向加锁。
	operationMu sync.Mutex
	mu          sync.Mutex
	store       *settings.Store
	values      settings.Values
	token, key  string
	active      *desktopGateway
	lastError   string
	build       BuildInfo
	closing     bool
	operation   string
	logs        *gateway.RequestLog
}

var errDesktopClosing = errors.New("程序正在退出")

type desktopSnapshot struct {
	values               settings.Values
	token, key           string
	active               *desktopGateway
	lastError, operation string
	closing              bool
}

func (c *desktopController) state() desktopSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return desktopSnapshot{values: c.values, token: c.token, key: c.key, active: c.active,
		lastError: c.lastError, operation: c.operation, closing: c.closing}
}

func (c *desktopController) withOperation(operation string, work func() error) error {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return errDesktopClosing
	}
	c.operation = operation
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.operation = ""
		c.mu.Unlock()
	}()
	return work()
}

func (c *desktopController) setLastError(err error) string {
	message := errorText(err)
	c.mu.Lock()
	c.lastError = message
	c.mu.Unlock()
	return message
}

func (c *desktopController) restart() error {
	return c.withOperation("restarting", func() error {
		err := c.restartGateway()
		c.setLastError(err)
		return err
	})
}

func (c *desktopController) stop() error {
	return c.withOperation("stopping", func() error {
		err := c.stopGateway()
		c.setLastError(err)
		return err
	})
}

func (c *desktopController) close() {
	// 先拒绝新操作，再等待已有保存或启停结束，最后回收唯一活动实例。
	c.mu.Lock()
	c.closing = true
	c.mu.Unlock()
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	_ = c.stopGateway()
}

// stopGateway 与 restartGateway 仅在持有 operationMu 时调用。
func (c *desktopController) stopGateway() error {
	c.mu.Lock()
	active := c.active
	c.active = nil
	c.mu.Unlock()
	if active == nil {
		return nil
	}
	active.requestMu.Lock()
	active.stopping = true
	active.requestMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := active.server.Shutdown(ctx)
	if err != nil {
		_ = active.server.Close()
	}
	<-active.serveDone
	active.requests.Wait()
	active.cancel()
	<-active.maintenanceDone
	active.transport.CloseIdleConnections()
	closeErr := active.audit.Close()
	if err != nil {
		return fmt.Errorf("在途请求超过停止时限，已终止连接: %w", err)
	}
	return closeErr
}

func (c *desktopController) restartGateway() error {
	state := c.state()
	if state.values.SetupRequired {
		return errors.New("请先在连接设置中填写实际使用的上游 API 地址并保存")
	}
	if err := c.stopGateway(); err != nil {
		return err
	}
	if state.values.AuthMode != settings.AuthClient && state.key == "" {
		return errors.New("请先在连接设置中填写上游 API Key")
	}
	cfg, err := c.store.Config(state.values)
	if err != nil {
		return err
	}
	ctx := context.Background()
	policy, err := storage.OpenPolicy(ctx, cfg.PolicyDB)
	if err != nil {
		return err
	}
	rules, loadErr := policy.Load(ctx)
	closeErr := policy.Close()
	if loadErr != nil {
		return loadErr
	}
	if closeErr != nil {
		return closeErr
	}
	engine, err := security.NewEngine(rules)
	if err != nil {
		return err
	}
	auditor, err := storage.OpenAudit(ctx, cfg.AuditDB, cfg.AuditRetentionDays, cfg.AuditMaxBytes)
	if err != nil {
		return err
	}
	client, err := newUpstreamHTTPClient(cfg.UpstreamHeaderTimeout)
	if err != nil {
		auditor.Close()
		return err
	}
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		auditor.Close()
		return err
	}
	var payloadError atomic.Value
	handler, err := gateway.NewHandler(gateway.Options{Upstream: upstream, Client: client, Engine: engine, RequestLog: c.requestLog(),
		Audit: auditor, LocalToken: state.token, UpstreamKey: state.key, ClientAuth: state.values.AuthMode == settings.AuthClient, Limits: config.LimitsConfig{
			MaxCompressedBytes: cfg.MaxBodyBytes, MaxDecompressedBytes: cfg.MaxBodyBytes, MaxConcurrent: cfg.MaxConcurrentRequests}, PayloadError: func(detail string) { payloadError.Store(detail) }})
	if err != nil {
		auditor.Close()
		return err
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		auditor.Close()
		return fmt.Errorf("无法监听代理地址 %s（端口可能已被占用或被系统限制），请更换本地监听端口: %w", cfg.Listen, err)
	}
	maintenance, cancel := context.WithCancel(ctx)
	active := &desktopGateway{audit: auditor, transport: client.Transport.(*http.Transport), cancel: cancel,
		maintenanceDone: make(chan struct{}), serveDone: make(chan struct{}), version: rules.Version}
	active.payloadError = &payloadError
	active.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.requestMu.Lock()
		if active.stopping {
			active.requestMu.Unlock()
			http.Error(w, "代理正在停止", http.StatusServiceUnavailable)
			return
		}
		active.requests.Add(1)
		active.requestMu.Unlock()
		defer active.requests.Done()
		handler.ServeHTTP(w, r)
	}), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
	active.running.Store(true)
	go func() { defer close(active.maintenanceDone); auditor.RunMaintenance(maintenance, time.Hour) }()
	go func() {
		defer close(active.serveDone)
		defer active.running.Store(false)
		_ = active.server.Serve(listener)
	}()
	c.mu.Lock()
	c.active = active
	c.mu.Unlock()
	return nil
}
