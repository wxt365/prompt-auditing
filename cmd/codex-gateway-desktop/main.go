package main

import (
	"bytes"
	"os"

	"github.com/xiaotaowang/prompt-auditing/internal/app"
	"github.com/xiaotaowang/prompt-auditing/internal/platform"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	var diagnostics bytes.Buffer
	code := app.Run([]string{"desktop"}, &diagnostics, &diagnostics, app.BuildInfo{Version: version, Commit: commit})
	if code != 0 {
		platform.ShowDesktopError(diagnostics.String())
	}
	os.Exit(code)
}
