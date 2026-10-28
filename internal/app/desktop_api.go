package app

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/gateway"
	"github.com/xiaotaowang/prompt-auditing/internal/settings"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func (c *desktopController) managementHandler(origin, session string) http.Handler {
	assets, _ := fs.Sub(desktopAssets, "web")
	files := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		if "http://"+r.Host != origin || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != origin) {
			http.Error(w, "来源不受支持", http.StatusForbidden)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Method != http.MethodGet || (r.URL.Path != "/" && r.URL.Path != "/app.js" && r.URL.Path != "/style.css" && r.URL.Path != "/logo.svg") {
				http.NotFound(w, r)
				return
			}
			files.ServeHTTP(w, r)
			return
		}
		authorization := r.Header.Get("Authorization")
		provided := strings.TrimPrefix(authorization, "Bearer ")
		if provided == authorization || subtle.ConstantTimeCompare([]byte(provided), []byte(session)) != 1 {
			http.Error(w, "请从托盘或菜单栏重新打开管理界面", http.StatusUnauthorized)
			return
		}
		if c.state().closing {
			http.Error(w, "程序正在退出", http.StatusServiceUnavailable)
			return
		}
		if err := c.managementAPI(w, r); err != nil {
			writeDesktopAPIError(w, err)
		}
	})
}

func (c *desktopController) managementAPI(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	switch {
	case r.URL.Path == "/api/check-upstream" && r.Method == http.MethodPost:
		return checkDesktopUpstream(w, r)
	case r.URL.Path == "/api/live-logs" && (r.Method == http.MethodGet || r.Method == http.MethodPut || r.Method == http.MethodDelete):
		logs := c.requestLog()
		if r.Method == http.MethodPut {
			var input struct {
				Enabled *bool `json:"enabled"`
			}
			if err := readDesktopJSON(w, r, &input); err != nil {
				return err
			}
			if input.Enabled == nil {
				return errors.New("必须指定是否开启实时日志")
			}
			logs.SetEnabled(*input.Enabled)
		} else if r.Method == http.MethodDelete {
			logs.Clear()
		}
		return writeDesktopJSON(w, logs.Snapshot())
	case (r.URL.Path == "/api/audits" || strings.HasPrefix(r.URL.Path, "/api/audits/")) && r.Method == http.MethodGet:
		return c.queryAudits(w, r)
	case r.URL.Path == "/api/status" && r.Method == http.MethodGet:
		state := c.state()
		cfg, err := c.store.Config(state.values)
		if err != nil {
			return err
		}
		running, healthy, version, payloadDetail := false, false, "", ""
		if state.active != nil {
			running = state.active.running.Load()
			healthy = state.active.audit.Healthy()
			version = state.active.version
			if state.active.payloadError != nil {
				payloadDetail, _ = state.active.payloadError.Load().(string)
			}
		}
		return writeDesktopJSON(w, map[string]any{"running": running, "healthy": healthy, "rule_version": version,
			"operation": state.operation, "setup_required": state.values.SetupRequired, "error": state.lastError, "payload_error": payloadDetail, "version": c.build.Version, "data_directory": filepath.Dir(cfg.PolicyDB)})
	case r.URL.Path == "/api/settings" && r.Method == http.MethodGet:
		state := c.state()
		return writeDesktopJSON(w, map[string]any{"settings": state.values, "key_configured": state.key != ""})
	case r.URL.Path == "/api/settings" && r.Method == http.MethodPut:
		var input struct {
			settings.Values
			UpstreamKey string `json:"upstream_key"`
		}
		if err := readDesktopJSON(w, r, &input); err != nil {
			return err
		}
		_, proxyPort, splitErr := net.SplitHostPort(input.Listen)
		_, managementPort, _ := net.SplitHostPort(r.Host)
		requestedPort, _ := strconv.Atoi(proxyPort)
		currentPort, _ := strconv.Atoi(managementPort)
		if splitErr == nil && currentPort > 0 && requestedPort == currentPort {
			return errors.New("该端口正用于 Web 管理页，请选择其他本地监听端口")
		}
		var restartError string
		err := c.withOperation("saving_settings", func() error {
			state := c.state()
			key := state.key
			if input.UpstreamKey != "" {
				key = strings.TrimSpace(input.UpstreamKey)
			}
			if input.AuthMode == settings.AuthClient {
				key = ""
			}
			// 设置成功落库后才发布新快照，保存失败时保留原代理。
			input.SetupRequired = false
			if err := c.store.Save(ctx, input.Values, state.token, key); err != nil {
				return err
			}
			c.mu.Lock()
			c.values, c.key = input.Values, key
			c.mu.Unlock()
			restartError = c.setLastError(c.restartGateway())
			return nil
		})
		if err != nil {
			return err
		}
		return writeDesktopJSON(w, map[string]any{"saved": true, "error": restartError})
	case r.URL.Path == "/api/token" && r.Method == http.MethodPost:
		state := c.state()
		if state.values.AuthMode == settings.AuthClient {
			return errors.New("客户端认证模式请继续使用客户端现有密钥")
		}
		return writeDesktopJSON(w, map[string]string{"token": state.token})
	case r.URL.Path == "/api/start" && r.Method == http.MethodPost:
		err := c.restart()
		if errors.Is(err, errDesktopClosing) {
			return err
		}
		return writeDesktopJSON(w, map[string]string{"error": errorText(err)})
	case r.URL.Path == "/api/stop" && r.Method == http.MethodPost:
		err := c.stop()
		if errors.Is(err, errDesktopClosing) {
			return err
		}
		return writeDesktopJSON(w, map[string]string{"error": errorText(err)})
	case r.URL.Path == "/api/rules" && r.Method == http.MethodGet:
		cfg, err := c.store.Config(c.state().values)
		if err != nil {
			return err
		}
		policy, err := storage.OpenPolicy(ctx, cfg.PolicyDB)
		if err != nil {
			return err
		}
		defer policy.Close()
		rules, err := policy.Load(ctx)
		if err != nil {
			return err
		}
		return writeDesktopJSON(w, rules)
	case r.URL.Path == "/api/rules" && r.Method == http.MethodPut:
		var input struct {
			Rules []storage.Rule `json:"rules"`
		}
		if err := readDesktopJSON(w, r, &input); err != nil {
			return err
		}
		for i := range input.Rules {
			rule := &input.Rules[i]
			rule.Name = strings.TrimSpace(rule.Name)
			if rule.ID == "" {
				if rule.Name == "" {
					return errors.New("请填写规则名称")
				}
				random := make([]byte, 16)
				if _, err := rand.Read(random); err != nil {
					return fmt.Errorf("生成规则标识: %w", err)
				}
				rule.ID = "rule." + hex.EncodeToString(random)
			}
		}
		var restartError string
		err := c.withOperation("saving_rules", func() error {
			state := c.state()
			cfg, err := c.store.Config(state.values)
			if err != nil {
				return err
			}
			policy, err := storage.OpenPolicy(ctx, cfg.PolicyDB)
			if err != nil {
				return err
			}
			if err := policy.ReplaceRules(ctx, input.Rules); err != nil {
				_ = policy.Close()
				return err
			}
			closeErr := policy.Close()
			restartError = state.lastError
			if state.active != nil {
				restartError = c.setLastError(c.restartGateway())
			}
			if closeErr != nil {
				restartError = c.setLastError(closeErr)
			}
			return nil
		})
		if err != nil {
			return err
		}
		return writeDesktopJSON(w, map[string]any{"saved": true, "error": restartError})
	default:
		http.NotFound(w, r)
		return nil
	}
}

func (c *desktopController) requestLog() *gateway.RequestLog {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.logs == nil {
		c.logs = &gateway.RequestLog{}
	}
	return c.logs
}

func (c *desktopController) queryAudits(w http.ResponseWriter, r *http.Request) error {
	cfg, err := c.store.Config(c.state().values)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if r.URL.Path != "/api/audits" {
		idText, resource, hasResource := strings.Cut(strings.TrimPrefix(r.URL.Path, "/api/audits/"), "/")
		id, err := strconv.ParseInt(idText, 10, 64)
		if err != nil || id <= 0 || (hasResource && resource != "request") {
			return errors.New("审计记录 ID 无效")
		}
		var record any
		if hasResource {
			record, err = storage.QueryAuditRequestBody(ctx, cfg.AuditDB, id)
		} else {
			record, err = storage.QueryAuditDetail(ctx, cfg.AuditDB, id)
		}
		if errors.Is(err, sql.ErrNoRows) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			return writeDesktopJSON(w, map[string]string{"error": "记录不存在或已按保留策略清理"})
		}
		if err != nil {
			return err
		}
		return writeDesktopJSON(w, record)
	}
	query := r.URL.Query()
	filter := storage.AuditFilter{Action: query.Get("action"), RequestID: query.Get("request_id"), RuleID: query.Get("rule_id"), Since: query.Get("since"), Until: query.Get("until")}
	filter.RuleName = query.Get("rule_name")
	if raw := query.Get("before"); raw != "" {
		filter.BeforeID, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || filter.BeforeID <= 0 {
			return errors.New("分页游标无效")
		}
	}
	if raw := query.Get("limit"); raw != "" {
		filter.Limit, err = strconv.Atoi(raw)
		if err != nil || filter.Limit <= 0 {
			return errors.New("每页数量无效")
		}
	}
	page, err := storage.QueryAudit(ctx, cfg.AuditDB, filter)
	if err != nil {
		return err
	}
	return writeDesktopJSON(w, page)
}

func errorText(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
func writeDesktopJSON(w http.ResponseWriter, value any) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(value)
}
func writeDesktopAPIError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusBadRequest
	if errors.Is(err, errDesktopClosing) {
		status = http.StatusServiceUnavailable
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
func readDesktopJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("请求必须使用 application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("配置内容无效或超过大小限制")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("请求只能包含一个 JSON 对象")
	}
	return nil
}
