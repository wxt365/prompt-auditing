# JSON 扩展统一兼容与审计

2026-10-28，版本 `trial-20261028.3`。

用户先后遇到 `/input/8/content/0/logprobs 未登记`、`/input/16/metadata 未登记`。旧逻辑已经递归提取请求字符串，却仍以根级和嵌套字段白名单拒绝可检查的 JSON；新增客户端字段会反复产生本地 422，且拒绝发生在内容规则和上游调用前。

## 当前策略

- Responses 和 Chat Completions 共用扩展策略。普通 JSON 扩展字段在根级、历史项、工具、内容和其他嵌套对象中均可保留；键名和字符串值按输入顺序递归参与审计，数字保持 `json.Number` 精度。通过检查且无替换时，网关沿用原始正文转发，不重建请求。
- 已知字段继续校验类型和必要的消息结构。新出现的非附件 JSON 类型不再因不在枚举里而拒绝，交由上游判断是否支持。支持历史元数据的 null、对象、数组和嵌套结构，以及非空 `annotations` 和 `logprobs` 扩展。
- 原有已知正文继续先替换再检查。扩展协议字段和所有键名默认不可替换，不能仅因某个扩展属性叫 `text` 或 `content` 就取得正文权限；此处命中替换规则时沿用 `unsafe_mask` 阻断，以免损坏协议含义。工具/模型名称、概率 token 等同样保持不可替换。
- 未支持的文件、音频和 Chat 图片仍拒绝。合法 Responses 图片在确认 `input_image` 类型和 URL/内嵌格式后原样保留；图片数据不做文本检查。普通类型 `profile` 不再因包含 `file` 子串被误判为附件。
- 非法 UTF-8/JSON、重复键、超过 128 层嵌套、已知字段类型错误、请求体超限、安全引擎异常或审计不可用仍拒绝。两种接口仍不混用 `input`/`messages`，不做协议转换。

这是出站 JSON 文本审计，不是任意编码内容、远程引用、加密内容、文件或图片文字的解析器。附件识别限制仍然存在，不能据此声称支持全部 API 类型或所有厂商扩展。上游拒绝的字段、模型或协议不会被网关擅自删除或转换；其 422 原样返回，并在实时日志标明上游 HTTP 422 和 `upstream_http_error`，区别于本地 `unsupported_payload`。

## 验证

- `TestSeventeenthHistoryItemMetadata` 覆盖第 17 个历史项在消息、推理、函数及自定义工具调用/输出和新增历史类型中的嵌套元数据，确认准确提取 `/input/16/metadata/nested/0/tag`。
- `TestJSONExtensionsArePreservedAndInspected` 覆盖双协议的根级、历史、内容、工具、新类型、引用及概率扩展；验证 null、空数组/对象、嵌套内容、转义键名和大整数原样保留。
- `TestJSONExtensionsEnforceRulesOnKeysAndValues` 覆盖扩展键名和值中的 block、warn 和不可安全替换，防止兼容处理绕过审计。
- `TestResponsesMixedHistoryExtensions` 同时包含推理、工具调用和输出、搜索历史、非空引用、概率与 bytes 数组、refusal、引用 ID、嵌套根元数据、工具选择和新增输出格式。验证仅表示网关可检查这些 JSON，不证明某个具体上游支持其业务语义。
- `TestJSONExtensionsCannotBypassAttachmentChecks` 覆盖附件藏于扩展对象，以及借用合法图片路径但使用错误类型的情况。
- `TestJSONExtensionsForwardingAuditAndLogs` 共 28 个网关场景：双协议、普通/gzip、原文转发、正文替换、扩展值/键阻断、不可安全替换、附件拒绝和上游 422；验证认证、路径、SSE、原始阻断审计及本地/上游日志归因。
- 全量 `go test ./...`、带 `codex_contract,native_e2e,performance` 标签的 vet 通过。新增 `FuzzJSONExtensionCoverage` 随机检查接受的扩展内容是否完整进入审计，并保持正确的替换权限。
- 现有性能回归通过：1 MiB 纯检测 P95 约 61 ms；本地假上游 SSE 额外首字节开销 P95 约 1 ms；64 KiB 正文、代表性规则、SQLite FULL 审计和实时采集，在双协议并发 1/10 下首字节 P95 约 7–32 ms。这些是当前机器的样本，不是生产环境时延承诺。

检查记录位于 `dist/extensions-20261028/`。验证使用回环地址上的模拟上游和测试凭证；没有读取用户真实密钥或原始会话，没有替换当前进程，也没有修改本机客户端或网关配置。用户原会话及真实上游仍需升级后验证。

## 分发

Windows x64 包为 `dist/codex-gateway-windows-x64-20261028-r3.zip`，仅包含 `codex-gateway.exe`、离线使用说明和 SHA-256 校验文件。包校验记录见同目录下的 `extensions-20261028/package-verification.json`。

从托盘退出旧版后启动新版，在运行状态确认 `trial-20261028.3`，保留现有配置重试原会话。无需删除会话、改客户端地址或清空审计数据。
