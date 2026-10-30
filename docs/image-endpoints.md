# 图片接口使用说明

## 入口与配置

| 本地接口 | 请求格式 |
| --- | --- |
| `POST /images/generations` | `application/json` |
| `POST /images/edits` | `application/json` 或 `multipart/form-data` |

新增入口不带版本前缀，`/v1/images/generations` 和 `/v1/images/edits` 返回 404。Chat Completions 仍接受 `/chat/completions` 和 `/v1/chat/completions`，Responses 使用 `/v1/responses`。截至 2026-10-29 未在 OpenAI 官方文档检索到 `/alpha/search` 的公开接口定义，暂不加入。

上游填写 Base URL，支持 HTTP 和 HTTPS，图片入口直接附加到该地址：

| 上游配置 | 图片生成实际转发地址 |
| --- | --- |
| `http://192.168.137.250:33000/v1/` | `http://192.168.137.250:33000/v1/images/generations` |
| `https://api.example.com/v1` | `https://api.example.com/v1/images/generations` |
| `https://api.example.com` | `https://api.example.com/images/generations` |

Gateway 不会为图片请求自动补 `/v1`。客户端如果在 Base URL 后自动附加 `/images/...`，本地 Base URL 设为 `http://127.0.0.1:18080`，不使用管理页面向 Responses 显示的 `/v1` 后缀。

所有请求都需要 Bearer 认证。“沿用客户端认证”使用客户端现有的上游密钥；“由网关配置上游 API Key”使用网关提供的本地令牌。以下命令假定已将对应凭证放入 `GATEWAY_BEARER` 环境变量，不要把凭证写入文档或提交到仓库。

## 请求示例

生成图片：

```bash
curl http://127.0.0.1:18080/images/generations \
  -H "Authorization: Bearer $GATEWAY_BEARER" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-image-1","prompt":"画一只白猫","size":"1024x1024"}'
```

上传图片并编辑，可重复 `image[]` 传入多张图片；单张图片也支持 `image` 字段，同一次请求不可混用两种名称：

```bash
curl http://127.0.0.1:18080/images/edits \
  -H "Authorization: Bearer $GATEWAY_BEARER" \
  -F 'model=gpt-image-1' \
  -F 'prompt=将背景改为蓝色' \
  -F 'image[]=@input.png'
```

JSON 图片引用编辑：

```bash
curl http://127.0.0.1:18080/images/edits \
  -H "Authorization: Bearer $GATEWAY_BEARER" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-image-1","prompt":"将背景改为蓝色","images":[{"image_url":"https://example.com/input.png"}]}'
```

每个引用必须在 `image_url` 与 `file_id` 中二选一。`image_url` 支持 HTTP/HTTPS 或 PNG、JPEG、WebP、GIF 的 Base64 data URL；`file_id` 需由上游已有文件提供，本次不增加文件上传 API。可选 `mask`、`markup` 使用相同引用对象；multipart 中则作为文件字段提交。

以上模型名仅为示例，实际可用模型、格式、尺寸及流式能力由你的上游决定。JSON 使用 `"stream":true`、multipart 使用 `-F 'stream=true'`，配合 `curl -N` 可接收 SSE；Gateway 原样转发正常 JSON/SSE 响应，不处理生成图片内容。

## 检测、审计与限制

- `prompt` 必须是非空字符串，是图片请求中唯一可脱敏字段。模型名、图片地址、文件 ID、其他文本字段、JSON 键、multipart 字段名、文件名和字段头参与检测，但不可替换；替换规则命中时阻断，告警规则命中时记录后放行。
- 图片二进制和已登记 data URL 不作为文本扫描；不会下载图片 URL、读取文件 ID 对应内容或做 OCR。图片内容中携带的敏感信息不在此检测范围。Base64 仅校验声明和编码，实际图片解码由上游完成。
- 无需脱敏时转发原始请求字节；脱敏 multipart 时仅重建封装、修改提示词，图片字节保持不变。支持整包 gzip，正文修改后移除失效的完整性 Header。
- multipart 最多 128 个部分、1 至 16 张输入图片；mask、markup 各最多一个，文本字段不得重复或伪装为文件。图片文件 Content-Type 接受 PNG、JPEG、WebP、GIF、application/octet-stream 或省略；文本只能是 UTF-8，可省略 Content-Type 或声明 text/plain。不接受部分级压缩或 Content-Transfer-Encoding。
- 阻断的 JSON 请求保存凭证脱敏后的 JSON 结构；阻断的 multipart 请求保存规范化 JSON，包含文本和文件名、字段头、字节大小、SHA-256，不包含文件二进制，无法从审计记录恢复原始图片上传包。普通放行、告警、脱敏仍只保存原有决策和完成记录。
- 保留现有并发、扫描超时和审计失败关闭机制。当前源码新安装默认整包限额为 1 GiB（1024 MiB，1073741824 字节），允许继续调大，压缩与解压均受限；Base64 和 multipart 开销计入限额。这是请求总大小，不是单张图片的最大原始大小。升级保留已有设置；若仍为 5 或 100 MiB，请在管理页将“最大请求体（MiB）”改为 1024 并保存应用，CLI 设置 `max_body_bytes: 1073741824` 后重启。已发布的 `0.1.3` 包仍默认 100 MiB。此调整不增加 PDF 附件支持。

整包限额选择依据（2026-10-30 核对）：官方[图片理解](https://developers.openai.com/api/docs/guides/images-vision#image-input-requirements)允许每次请求总计 512 MB；[图片编辑上传](https://developers.openai.com/api/reference/go/resources/images/methods/edit)允许最多 16 张、每张小于 50 MB。1 GiB 为这些大小及 multipart 封装预留空间，网关不额外收紧单图大小、模型名称或图片尺寸，具体合法性由上游判断。该值仅表示接收上限，不代表已完成 1 GiB 实际上传、扫描或并发性能验收。

常见响应：401 认证缺失或错误；403 命中阻断规则；413 请求体超限；415 Content-Type 不支持；422 请求结构不支持；503 扫描或审计不可用。上游错误状态码与安全处理后的诊断仍按原有逻辑返回。

接口格式参考 OpenAI 官方 [图片生成](https://developers.openai.com/api/reference/resources/images/methods/generate) 和 [图片编辑](https://developers.openai.com/api/reference/resources/images/methods/edit) 文档。Gateway 的本地入口、检测范围和限制以本说明为准。
