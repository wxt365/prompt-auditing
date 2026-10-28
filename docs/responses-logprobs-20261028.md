# Responses 历史消息 logprobs 兼容修复

2026-10-28，发行版本 `trial-20261028.2`。

截图记录显示 `POST /v1/responses` 在本地以 422 拒绝，上游 HTTP 为空，具体路径为 `/input/8/content/0/logprobs 未登记`。源码确认 `output_text` 内容仅登记了 `type`、`text` 和空 `annotations`，遗漏 `logprobs`。这是请求结构校验失败，发生在内容规则检查前；同一历史载荷被客户端重试时，仍会被本地拒绝。截图本身不能确定该字段的实际取值或客户端触发重试的具体机制。

修复仅在 `output_text` 内容内登记 `logprobs`，支持 null、空数组，以及固定字段的概率数组：每项必须包含字符串 `token` 和数值 `logprob`，可带 `top_logprobs` 数组，其子项同样包含 `token`、`logprob`。其他未知字段或错误类型仍拒绝。普通正文仍参与原有替换与阻断；概率 token 文本也参与审计，保持不可替换，命中替换规则时沿用“不可安全替换，转为阻断”的已有行为，避免悄悄泄露匹配文本或破坏分词与概率对应关系。

验证证据：

- 通过 Go overlay 使用旧登记表，未改动工作区源码，已复现第 9 条消息的 `/input/8/content/0/logprobs 未登记`。旧逻辑对 null、空数组和固定结构的非空数组均拒绝。结果位于 `dist/logprobs-20261028/legacy-reproduction.txt`。
- 修复后提取和序列化保持字段；错误类型、未知字段及不支持位置仍拒绝，保留准确路径。主 token 和候选 token 中的测试关键字仍会被审计。
- 网关验证普通及 gzip 两种请求，共 18 个场景：空数组、null、非空数组、正文替换、正文阻断、token 阻断、不可安全替换、候选 token 阻断和未知字段拒绝。核对上游路径与认证、原文转发、SSE 响应、审计及实时完成状态。正文替换后概率元数据保持原值。
- 全量 Go 测试、带 `codex_contract,native_e2e,performance` 标签的 vet 和 JavaScript 语法检查通过；定向回归输出位于 `dist/logprobs-20261028/regression.txt`。
- 新包 `dist/codex-gateway-windows-x64-20261028-r2.zip` 已核对 ZIP CRC、包内与外部 SHA-256、实际版本、Windows x64 GUI 格式、CGO 禁用、兼容函数及网页资源嵌入。包内仅有 EXE、离线说明与校验文件，旧包未修改。

当前环境无法访问 OpenAI Docs 官方参考页，未据此声明完整 Responses Schema 兼容。此次验证使用合成历史和本地模拟上游，未读取用户请求原文、认证文件或真实规则内容，未向用户上游发送模型请求，未更改本机配置或启动新版桌面 EXE。用户需退出旧实例并启动新版，保留原配置后重试原会话，验证真实客户端请求。
