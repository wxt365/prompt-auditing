# Codex Security Gateway MVP 验收证据矩阵

| 项目 | 内容 |
| --- | --- |
| 权威设计 | `docs/codex-security-gateway-mvp-design.md` 0.7 |
| 核验日期 | 2026-08-04 |
| 本机环境 | Apple Silicon macOS，Go 1.26.5 |
| 状态定义 | `通过` 表示当前仓库自动化证据已覆盖；`部分通过` 表示实现或较低层测试存在，但缺少验收标准要求的完整层级；`待环境` 表示缺少目标平台、授权或外部资源；`待确认` 表示产品或安全参数尚未冻结。 |

> 2026-10-28 更新：下表为历史 MVP 验收记录，其中“未知字段/未知工具类型一律拒绝”的 AC-007 策略已被统一 JSON 扩展审计取代。当前回归、测试边界和试用包见 [JSON 扩展兼容](json-extensions-20261028.md)；不沿用旧结论作为新策略的验证证据。

> 2026-10-30 更新：默认请求体上限先从 5 MiB 调整为 100 MiB（已发布 0.1.3 包），随后源码按官方图片接口大小要求放宽为 1 GiB，管理页允许继续调大，旧的显式限制保留。下表 AC-015 的 5 MiB 描述为历史记录，不代表当前默认值；原性能数据不证明 1 GiB 请求或大请求并发性能。

## AC 证据

| AC | 状态 | 当前证据 | 未闭合项 |
| --- | --- | --- | --- |
| AC-001 | 部分通过 | `TestUpstreamStatusAndBodyAreForwardedWithoutRetry` 和 SQLite 集成测试覆盖普通 JSON 请求及假上游响应透传。真实 Codex `0.144.5` 捕获请求固定为 `"stream":true`，本机 `codex exec --help` 和功能列表未提供关闭流式 Responses 的选项。 | 缺少 Codex CLI 发起非流式 Responses 请求的原生 E2E；需由产品负责人修订该要求或提供目标 Codex 版本及可验证的非流式配置。 |
| AC-002 | 通过 | `TestSSEBodyAndStatusAreTransparent` 覆盖事件正文和顺序；`TestSSEMidStreamFailureIsAudited` 覆盖中途断流；`TestDarwinArtifactWithRealCodex` 验证 Codex `0.144.5` 经原生 Gateway 解析完整 SSE 并得到 `OK`，测试进程由 `sandbox-exec` 限制为仅可访问本机回环地址。 | 无。 |
| AC-003 | 通过 | `TestBlockDoesNotCallUpstreamAndAuditsRequest` 验证 `403`、固定错误码/提示、上游零调用和响应不泄露命中详情。 | 无。 |
| AC-004 | 通过 | Codex 0.144.5 真实契约和脱敏夹具覆盖 instructions、input、`function`、`custom`、`tool_search`、`web_search` 工具字段及参数 Schema 文本提取；`TestEngineScansToolName`、`TestMaskRuleBlocksProtocolFieldsAndDynamicKeys` 和 `TestToolOutputBlockDoesNotCallUpstream` 验证工具名称、协议字段、动态对象键、Schema 属性名、`required` 引用及工具输出均参与检测，不可安全替换的位置提升为阻断。 | 无。 |
| AC-005 | 通过 | `TestEngineMaskIsOnePassAndNonCascading` 和 `TestMaskReplacesAuthorizationAndPreservesGzip` 覆盖多组非级联替换及上游正文；后者同时验证正文改变后删除 `Content-MD5`、`Digest`、`Etag`、`Content-Digest` 和 `Repr-Digest`，`TestNoOpMaskPreservesContentIntegrityHeaders` 验证正文实际未变化时保留原始完整性 Header。 | 无。 |
| AC-006 | 通过 | `TestActionPriority`、`TestEngineBlockAndRecordAllKeywords` 和 SQLite 审计明细测试覆盖固定优先级、全部规则命中及关键字去重。 | 无。 |
| AC-007 | 通过 | `TestValidationOrderAndStableErrorCodes`、`TestExtractRejectsUnknownTextAndAttachments`、`TestExtractPreservesTextOrderAndRejectsDuplicateKeys` 和 `TestDuplicateContentHeadersAreRejected` 覆盖非法 JSON/UTF-8、重复键、根级及嵌套未知文本字段、未知工具类型、实际附件、重复 Content Header 和 Content-Type；`TestExtractAllowsAttachmentNamedJSONSchemaProperties` 验证工具/结构化输出 Schema 中同名属性不被误判为附件，并确认属性名与 `required` 引用参与检测但不可脱敏；Gateway 层验证失败请求上游零调用。 | 无。 |
| AC-008 | 通过 | `TestMaskReplacesAuthorizationAndPreservesGzip` 验证 gzip 解压检测、脱敏后重编码和假上游解析。 | 无。 |
| AC-009 | 通过 | 转发前审计失败和事务明细失败均验证失败关闭；`TestSecurityEnginePanicFailsClosed`、`TestHandlerAddsSecurityInspectionDeadline`、`TestInspectionCancellationAndMatchLimitFailClosed` 和 `TestSecurityInspectionLimitFailsClosedWithoutCallingUpstream` 验证引擎异常、2 秒扫描 Deadline、取消及 10,000 条命中上限均返回稳定 `503` 且上游零调用；关键词、正则和 IPv4 检测均逐次生成命中，Go 正则使用 RE2。 | 无。 |
| AC-010 | 部分通过 | 配置校验强制 `listen` 为回环 IP，实际发布产物只监听 `127.0.0.1:38181`。Docker 独立网络命名空间使用 `host.docker.internal` 仍可取得 `/healthz` 200；正向控制端口同样可达，Python 对照服务确认 Docker Desktop 代理后的宿主源地址为 `127.0.0.1`。 | 缺少物理另一主机连接失败证据；且若验收范围包含本地 Docker Desktop 容器，“TCP 连接失败”当前不成立，需产品修订 AC-010 或增加宿主防火墙/容器网络策略。 |
| AC-011 | 通过 | `TestMaskReplacesAuthorizationAndPreservesGzip` 验证 Host 固定、上游凭证替换、连接专用 Header、`Forwarded` 和 `X-Forwarded-*` 删除；`TestUpstreamRedirectIsReturnedWithoutFollowing` 验证不跟随上游重定向并删除 `Location`；`TestLoadAcceptsFixedHTTPAndHTTPSUpstreams`、`TestLoadRejectsUnsupportedOrNonFixedUpstreams` 和 `TestHTTPUpstreamWithTrailingSlashUsesResponsesPath` 验证固定 HTTP/HTTPS 双协议、其他 scheme 拒绝及 `/v1/` 路径归一化；目标 URL 仍只由启动配置生成。 | 无。 |
| AC-012 | 通过 | `TestUpstreamStatusAndBodyAreForwardedWithoutRetry` 覆盖 400/401/429/500；`TestUpstreamErrorRedactsConfiguredCredentials` 覆盖 gzip、JSON Unicode 转义、正文/Header 凭证脱敏和长度重建；上游 Transport 保留有界 TCP、HTTPS TLS 握手、响应 Header 和空闲连接超时；`TestStartWarnsWhenUpstreamUsesHTTP` 验证 HTTP 模式输出明文传输警告；`TestSSEMidStreamFailureIsAudited` 覆盖断流诊断。 | 无。 |
| AC-013 | 通过 | 配置未知字段、数据库同路径及硬链接同文件、高 Schema 版本、权限过宽、已存在共享目录不被修改、NFKC 映射冲突和重复初始化均有测试；`TestOpenRejectsEmptyDatabasesWithoutInitializingThem` 验证打开路径拒绝空策略库和审计库且不写入 Schema 或默认规则，`TestStartAndCheckConfigRejectEmptiedDatabases` 进一步覆盖两个 CLI 命令与两种空库组合；`TestInvalidRuleSetsAreRejected` 逐项覆盖重复规则 ID、非法正则、空映射和同一源对应多个目标。 | 无。 |
| AC-014 | 通过 | `TestGatewayUsesPolicyAndAuditDatabasesEndToEnd`、`TestAuditEventAndMatchesCommitAtomically` 和 `TestBlockAuditRedactsConfiguredCredentials` 验证 UTC 事件、全部去重关键字、结构化完整阻断请求体，以及本地 Token、上游 API Key 不进入 SQLite、WAL、SHM 或命中明细；数据库 Schema 不包含 Header 或凭证字段。 | 无。 |
| AC-015 | 待确认 | 2026-08-03 最终性能复测通过生产 `Inspect(context.Context, Payload)` 路径，本机得到：1 MiB 纯检测 P95 `61.656292 ms`；SSE 首字节额外代理延迟 P95 `336.75 us`；第 11 个并发请求返回 `429`。 | 第 18 节的 5 MiB、100 ms、150 ms、并发 10 仍需产品负责人冻结，且需记录正式基准机规格。 |
| AC-016 | 待环境 | `scripts/build-release.sh` 已交叉编译出 Windows AMD64 PE32+，元数据为 `CGO_ENABLED=0`；`TestWindowsArtifactCore` 已实现启动、ACL 后配置校验、阻断、替换、SQLite 审计、上游认证替换和 Ctrl+Break 优雅停止，并成功交叉编译为 Windows AMD64 PE32+ 测试二进制。 | 缺少 Windows AMD64 目标机原生执行结果。 |
| AC-017 | 通过 | 新构建的 macOS ARM64 Mach-O 产物通过 `TestDarwinArtifactCore` 和 `TestDarwinArtifactWithRealCodex`：覆盖启动、配置校验、阻断、替换、SQLite 审计、上游认证替换、真实 Codex `0.144.5` SSE 和优雅停止；真实 Codex 仅允许访问本机回环地址。 | 无。 |
| AC-018 | 待环境 | 两个平台从同一 Go 源码、规则 Schema、审计 Schema 和错误码构建。 | 缺少 Windows 与 macOS 原生契约结果对比，源码一致不能替代双平台运行证据。 |
| AC-019 | 通过 | `TestAuditCleanupDoesNotChangePolicy` 和 `TestAuditCleanupEnforcesMaximumDatabaseSize` 验证双库隔离、时间清理、按最旧事件进行容量淘汰、清理后数据库实际大小不超过上限，以及策略版本和处置不变。 | 无。 |
| AC-020 | 通过 | 存储原子事务测试和真实 SQLite 集成测试通过触发器强制明细失败，验证主事件回滚且请求不发送上游。 | 无。 |
| AC-021 | 通过 | `TestPolicyWritesAndVersionIncrementAreAtomic` 验证规则更新与版本递增同事务、失败不变更；`TestPolicyLoadReturnsOneTransactionalSnapshotDuringConcurrentWrites` 使用独立 SQLite 连接并发写入，验证版本、规则主表和子表始终来自同一个只读事务快照。 | 无。 |

## 已执行命令

```bash
GOCACHE=/private/tmp/prompt-auditing-go-cache GOPROXY=off GOSUMDB=off go vet ./...
GOCACHE=/private/tmp/prompt-auditing-go-cache GOPROXY=off GOSUMDB=off go test -count=1 -race ./...
GOCACHE=/private/tmp/prompt-auditing-go-cache GOPROXY=off GOSUMDB=off go test -count=1 -tags sqlite_experimental ./...
GOCACHE=/private/tmp/prompt-auditing-go-cache GOPROXY=off GOSUMDB=off go test -count=1 -tags jsonl_experimental ./...
GOCACHE=/private/tmp/prompt-auditing-go-cache GOPROXY=off GOSUMDB=off go test -tags codex_contract -run '^$' ./tests/contract
RUN_CODEX_CONTRACT=1 GOCACHE=/private/tmp/prompt-auditing-go-cache GOPROXY=off GOSUMDB=off sandbox-exec -p '(version 1)(allow default)(deny network-outbound (require-not (remote ip "localhost:*")))' go test -count=1 -tags codex_contract -run TestCodex0144ResponsesContract -v ./tests/contract
GOCACHE=/private/tmp/prompt-auditing-go-cache GOPROXY=off GOSUMDB=off go test -tags native_e2e -run '^$' ./tests/e2e
GOCACHE=/private/tmp/prompt-auditing-go-cache GOPROXY=off GOSUMDB=off GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -exec=true ./...
GOCACHE=/private/tmp/prompt-auditing-go-cache GOPROXY=off GOSUMDB=off GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c -tags native_e2e -o /private/tmp/prompt-auditing-windows-e2e.test.exe ./tests/e2e
GOCACHE=/private/tmp/prompt-auditing-go-cache GOPROXY=off GOSUMDB=off go test -count=1 -tags performance -v ./tests/performance
GOCACHE=/private/tmp/prompt-auditing-go-cache GOPROXY=off GOSUMDB=off RELEASE_OUTPUT_DIR=/private/tmp/prompt-auditing-release-complete ./scripts/build-release.sh 0.1.0-test
shasum -a 256 -c SHA256SUMS
GATEWAY_BINARY=/private/tmp/prompt-auditing-release-complete/codex-gateway-darwin-arm64 go test -count=1 -tags native_e2e -run 'TestDarwinArtifact(Core|WithRealCodex)$' -v ./tests/e2e
```

## 发布结论

当前状态不是完整发布验收通过。已证明自动化测试、建议性能基线、macOS ARM64 原生产物及真实 Codex E2E、Windows AMD64 产物与原生 E2E 测试的交叉编译、版本注入和校验和；未证明 Codex 非流式 Responses 原生 E2E、跨主机连接失败、Windows 目标机原生 E2E、双平台原生结果对比、公网 OpenAI 联调，以及第 18 节产品/安全负责人确认项。
