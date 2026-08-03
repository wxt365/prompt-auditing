package main

import (
	"os"

	"github.com/xiaotaowang/prompt-auditing/internal/app"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	os.Exit(app.Run(os.Args[1:], os.Stdout, os.Stderr, app.BuildInfo{Version: version, Commit: commit}))
}
