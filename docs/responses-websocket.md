# Responses 长连接与查询

以下能力包含在 `0.1.7` 测试包中。上游必须自身支持对应接口。

## 支持的路径

| 请求 | 用途 |
| --- | --- |
| `POST /v1/responses`、`POST /responses` | 创建响应，沿用原有 JSON / SSE 流程 |
| `GET /v1/responses`、`GET /responses`，带 WebSocket 升级头 | 建立持久连接，在连接内发送请求并接收响应事件 |
| `GET /v1/responses/{response_id}`、`GET /responses/{response_id}` | 查询指定响应，支持 JSON 或 SSE |

普通 GET 不带响应 ID、也不进行协议升级时，返回 405，不伪造成功或响应列表。此轮未增加其他 Responses 子接口。

两种入口使用同一套认证与规则。上游配置为 `http://192.168.137.250:33000/v1/` 时，长连接使用对应的 `ws://192.168.137.250:33000/v1/responses`；HTTPS 上游对应 WSS。路径拼接不会重复添加 `/v1`。客户端仍访问本地代理，无需改变认证模式。

## WebSocket 请求

以本地默认端口为例，客户端通过 `ws://127.0.0.1:18080/v1/responses` 或 `ws://127.0.0.1:18080/responses` 建立连接，使用 `Authorization: Bearer <现有客户端密钥或本地令牌>`，与 HTTP 模式一致。原生客户端一般不发送 Origin；发送 Origin 时必须与本地网关同源。

连接建立后发送 JSON 文本消息，例如：

```json
{
  "type": "response.create",
  "model": "你的模型名称",
  "input": "请回复 OK",
  "store": false
}
```

收到上游响应事件后，可在同一连接内继续发送 `response.create`，使用 `previous_response_id` 和本轮新增的 `input`。也接受 `response.steer`，用于支持此事件的上游追加指令。`stream_id`、预热参数 `generate: false` 及普通 JSON 扩展字段参与检测，未脱敏时保留原始字节；其业务语义由上游处理。无需添加 HTTP SSE 的 `stream: true`。

每条客户端事件独立经过结构检查、限时规则检测、脱敏和转发前审计。文本中的可替换内容按规则脱敏；模型名称、角色、工具名称、事件类型、流 ID、动态键等协议内容命中脱敏规则时阻断，不改写协议。图片沿用现有 Responses 校验与二进制豁免，仍不做图片内容识别。

规则阻断时，仅拒绝当前事件，返回 JSON `error` 事件，包含状态、错误码及网关请求 ID；有效的 `stream_id` 会随错误返回。连接可继续提交安全事件。未知客户端事件、二进制消息或非法 JSON 不会透传。安全引擎或审计故障关闭连接，避免继续发送未审计内容。

连接占用一个并发名额，每条消息受配置中的请求体上限约束；不协商 WebSocket 消息压缩。握手、写入设有超时，连接最长一小时。上游断开、客户端断开以及网关停止、重启或应用配置时，都会清理连接和转发任务。网关不会自动重放事件。

## 响应查询

```text
GET /v1/responses/resp_example
GET /responses/resp_example?stream=true&starting_after=3
```

示例 ID 请替换为上游返回的实际 ID。支持官方参数 `stream`、`starting_after`、`include_obfuscation`、`include` / `include[]`，不接受未知参数、非法类型、GET 正文、请求体编码或协议升级。校验通过的查询参数原样发送上游；ID 与参数也参与规则检测，不能脱敏改写。上游仍负责校验响应是否存在、访问权限和具体参数取值。

查询参数不会进入接口路径日志；放行事件不保存请求正文。阻断事件沿用既有审计策略，保存凭证脱敏后的检测载荷。

## 日志和验证边界

实时日志保留客户端使用的版本前缀，路径仍按现有策略隐藏疑似凭证和较长的 ID。长连接握手以及连接内每条客户端请求分别记录，消息请求 ID 可用于检索审计。消息的 `websocket_forwarded` 记录只表示已检查并发送到上游，不表示模型生成完成；模型完成状态以收到的 `response.completed` 等上游事件为准。连接关闭另记 `websocket_closed`。WebSocket 错误事件及握手错误中的已知凭证会被脱敏。

本机模拟上游测试覆盖双路径、HTTP/HTTPS 上游、多轮事件、阻断 / 告警 / 脱敏、协议字段及动态键、非法消息、大小和并发限制、审计失败关闭及停机清理。这些测试不等同于真实 Codex / Harness 与实际上游的联调结果。

官方参考：[WebSocket 模式](https://developers.openai.com/api/docs/guides/websocket-mode)、[连接接口](https://developers.openai.com/api/reference/resources/responses/methods/connect)、[查询指定响应](https://developers.openai.com/api/reference/resources/responses/methods/retrieve)。
