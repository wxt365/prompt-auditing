package settings

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/platform"
	_ "modernc.org/sqlite"
)

type Values struct {
	SetupRequired         bool   `json:"setup_required"`
	AuthMode              string `json:"auth_mode"`
	Listen                string `json:"listen"`
	Upstream              string `json:"upstream"`
	MaxBodyBytes          int64  `json:"max_body_bytes"`
	MaxConcurrentRequests int    `json:"max_concurrent_requests"`
	AuditRetentionDays    int    `json:"audit_retention_days"`
	AuditMaxBytes         int64  `json:"audit_max_bytes"`
}

const (
	AuthClient  = "client"
	AuthGateway = "gateway"
)

type Store struct {
	db        *sql.DB
	directory string
}

func Open(directory string) (*Store, error) {
	directory, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	if err := platform.SecureDir(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, "settings.db")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	created := err == nil
	ready := false
	defer func() {
		if created && !ready {
			// 首次初始化失败时清理本次创建的库，避免下次启动被空设置库阻塞。
			_ = os.Remove(path)
		}
	}()
	if created {
		if err := file.Close(); err != nil {
			return nil, err
		}
		if err := platform.SecureFile(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := platform.ValidateSecureFile(path); err != nil {
		return nil, err
	}
	// 使用回滚日志，避免在设置库中额外创建持久 WAL/SHM 文件。
	uriPath := filepath.ToSlash(path)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: uriPath}).String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db, directory: directory}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err != nil {
		db.Close()
		return nil, err
	}
	if created {
		_, err = db.ExecContext(ctx, `CREATE TABLE settings (id INTEGER PRIMARY KEY CHECK(id = 1), version INTEGER NOT NULL, value TEXT NOT NULL, local_token BLOB NOT NULL, upstream_key BLOB NOT NULL)`)
		if err == nil {
			random := make([]byte, 32)
			if _, err = rand.Read(random); err == nil {
				err = store.Save(ctx, Values{SetupRequired: true, AuthMode: AuthClient, Listen: "127.0.0.1:18080", Upstream: "https://api.openai.com/v1", MaxBodyBytes: config.DefaultMaxBodyBytes, MaxConcurrentRequests: 10, AuditRetentionDays: 30, AuditMaxBytes: 100 << 20}, hex.EncodeToString(random), "")
			}
		}
		if err != nil {
			db.Close()
			return nil, err
		}
	}
	if _, _, _, err := store.Load(ctx); err != nil {
		db.Close()
		return nil, err
	}
	ready = true
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Config(values Values) (config.Config, error) {
	if values.AuthMode != "" && values.AuthMode != AuthClient && values.AuthMode != AuthGateway {
		return config.Config{}, errors.New("认证方式无效")
	}
	if values.Listen == "" || values.MaxBodyBytes <= 0 || values.MaxConcurrentRequests <= 0 || values.AuditRetentionDays <= 0 || values.AuditMaxBytes <= 0 {
		return config.Config{}, errors.New("监听地址不能为空，请求限制与审计保留参数必须大于零")
	}
	return config.Prepare(config.Config{Version: 1, Listen: values.Listen, Upstream: values.Upstream,
		PolicyDB: "policy.db", AuditDB: "audit.db", MaxBodyBytes: values.MaxBodyBytes,
		MaxConcurrentRequests: values.MaxConcurrentRequests, AuditRetentionDays: values.AuditRetentionDays,
		AuditMaxBytes: values.AuditMaxBytes}, s.directory)
}

func (s *Store) Load(ctx context.Context) (Values, string, string, error) {
	var values Values
	var version int
	var raw string
	var token, key []byte
	if err := s.db.QueryRowContext(ctx, "SELECT version, value, local_token, upstream_key FROM settings WHERE id = 1").Scan(&version, &raw, &token, &key); err != nil {
		return values, "", "", err
	}
	if version != 1 {
		return values, "", "", fmt.Errorf("不支持的设置版本 %d", version)
	}
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return values, "", "", err
	}
	if _, err := s.Config(values); err != nil {
		return values, "", "", err
	}
	plainToken, err := platform.UnprotectSecret(token)
	if err != nil {
		return values, "", "", err
	}
	plainKey, err := platform.UnprotectSecret(key)
	if err != nil {
		return values, "", "", err
	}
	if len(plainToken) < 32 || string(plainToken) == string(plainKey) {
		return values, "", "", errors.New("保存的本地令牌无效")
	}
	if values.AuthMode == "" {
		// 兼容升级前的设置：已有密钥保留网关认证，未配置密钥使用客户端认证。
		values.AuthMode = AuthClient
		if len(plainKey) != 0 {
			values.AuthMode = AuthGateway
		}
	}
	return values, string(plainToken), string(plainKey), nil
}

func (s *Store) Save(ctx context.Context, values Values, token, key string) error {
	if values.AuthMode == AuthClient {
		key = ""
	}
	if _, err := s.Config(values); err != nil {
		return err
	}
	if len(token) < 32 || token == key {
		return errors.New("本地令牌至少需要 32 字节，且必须与上游密钥不同")
	}
	sealedToken, err := platform.ProtectSecret([]byte(token))
	if err != nil {
		return err
	}
	sealedKey, err := platform.ProtectSecret([]byte(key))
	if err != nil {
		return err
	}
	if sealedKey == nil {
		sealedKey = []byte{}
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO settings(id, version, value, local_token, upstream_key) VALUES(1, 1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET value=excluded.value, local_token=excluded.local_token, upstream_key=excluded.upstream_key`, string(raw), sealedToken, sealedKey)
	return err
}
