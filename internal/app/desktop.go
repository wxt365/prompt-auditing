package app

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/platform"
	"github.com/xiaotaowang/prompt-auditing/internal/settings"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

//go:embed web/*
var desktopAssets embed.FS

func (r runner) desktop(args []string) error {
	if len(args) != 0 {
		return errors.New("desktop 命令不接受配置文件或其他参数")
	}
	unlock, err := platform.LockDesktop()
	if err != nil {
		return err
	}
	defer unlock()
	base, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	directory := filepath.Join(base, "CodexSecurityGateway")
	_, settingsErr := os.Stat(filepath.Join(directory, "settings.db"))
	firstRun := errors.Is(settingsErr, os.ErrNotExist)
	store, err := settings.Open(directory)
	if err != nil {
		return fmt.Errorf("打开桌面设置: %w", err)
	}
	defer store.Close()
	values, token, key, err := store.Load(context.Background())
	if err != nil {
		return err
	}
	controller := &desktopController{store: store, values: values, token: token, key: key, build: r.build}
	cfg, err := store.Config(values)
	if err != nil {
		return err
	}
	if err := initializeDesktopDatabases(cfg); err != nil {
		return err
	}
	if !values.SetupRequired && (values.AuthMode == settings.AuthClient || key != "") {
		_ = controller.restart()
	}
	showInitially := firstRun || values.SetupRequired || (values.AuthMode != settings.AuthClient && key == "") || controller.lastError != ""
	defer controller.close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		listener.Close()
		return err
	}
	session := hex.EncodeToString(random)
	origin := "http://" + listener.Addr().String()
	server := &http.Server{Handler: controller.managementHandler(origin, session), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			_ = server.Close()
		}
	}()
	go func() { _ = server.Serve(listener) }()
	open := func() {
		if err := platform.OpenBrowser(origin + "/#" + session); err != nil {
			platform.ShowDesktopError(err.Error())
		}
	}
	return platform.RunTray(open, showInitially)
}

func initializeDesktopDatabases(cfg config.Config) error {
	_, policyErr := os.Stat(cfg.PolicyDB)
	_, auditErr := os.Stat(cfg.AuditDB)
	if errors.Is(policyErr, os.ErrNotExist) && errors.Is(auditErr, os.ErrNotExist) {
		return storage.InitDatabases(context.Background(), cfg.PolicyDB, cfg.AuditDB)
	}
	if policyErr != nil || auditErr != nil {
		return errors.New("策略库或审计库缺失，请恢复完整数据库，程序不会覆盖现有数据")
	}
	policy, err := storage.OpenPolicy(context.Background(), cfg.PolicyDB)
	if err != nil {
		return err
	}
	_, loadErr := policy.Load(context.Background())
	closeErr := policy.Close()
	if loadErr != nil {
		return loadErr
	}
	if closeErr != nil {
		return closeErr
	}
	return storage.CheckAudit(context.Background(), cfg.AuditDB)
}
