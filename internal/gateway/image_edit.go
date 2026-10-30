package gateway

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
	"unicode/utf8"

	"github.com/xiaotaowang/prompt-auditing/internal/security"
)

const maxImageEditParts = 128

type imageEditPart struct {
	header textproto.MIMEHeader
	data   []byte
	file   bool
}

// 二进制仅保留在转发对象中，审计载荷只包含文本、文件元信息和摘要。
func extractImageEditMultipart(body []byte, boundary string) (security.Payload, func(security.Payload) ([]byte, error), error) {
	var payload security.Payload
	if err := multipart.NewWriter(io.Discard).SetBoundary(boundary); err != nil {
		return payload, nil, fmt.Errorf("multipart 分隔符无效: %w", err)
	}
	var parts []imageEditPart
	var descriptions []any
	fields := make(map[string]bool)
	images := 0
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := reader.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return payload, nil, fmt.Errorf("multipart 无法解析: %w", err)
		}
		if len(parts) >= maxImageEditParts {
			return payload, nil, fmt.Errorf("multipart 超过 %d 个字段", maxImageEditParts)
		}
		if len(part.Header.Values("Content-Disposition")) != 1 || len(part.Header.Values("Content-Type")) > 1 {
			return payload, nil, fmt.Errorf("multipart 字段头重复或缺失")
		}
		for key := range part.Header {
			if strings.EqualFold(key, "Content-Transfer-Encoding") || strings.EqualFold(key, "Content-Encoding") {
				return payload, nil, fmt.Errorf("不支持 multipart 字段编码")
			}
		}
		disposition, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if err != nil || disposition != "form-data" || params["name"] == "" {
			return payload, nil, fmt.Errorf("multipart 字段声明无效")
		}
		name := params["name"]
		filename, file := params["filename"]
		if !utf8.ValidString(name) || !utf8.ValidString(filename) {
			return payload, nil, fmt.Errorf("multipart 字段名或文件名包含非法 UTF-8")
		}
		if name == "image" || name == "image[]" || name == "mask" || name == "markup" {
			if !file || filename == "" {
				return payload, nil, fmt.Errorf("图片字段 %s 必须是文件", name)
			}
			if raw := part.Header.Get("Content-Type"); raw != "" {
				kind, _, err := mime.ParseMediaType(raw)
				if err != nil {
					return payload, nil, fmt.Errorf("图片 Content-Type 无效")
				}
				switch kind {
				case "image/png", "image/jpeg", "image/webp", "image/gif", "application/octet-stream":
				default:
					return payload, nil, fmt.Errorf("未支持的图片 Content-Type")
				}
			}
			if name == "image" || name == "image[]" {
				images++
				if images > 16 || (name == "image" && fields["image[]"]) || (name == "image[]" && fields["image"]) {
					return payload, nil, fmt.Errorf("图片数量超过限制或混用 image 与 image[]")
				}
			} else if fields[name] {
				return payload, nil, fmt.Errorf("图片字段 %s 重复", name)
			}
		} else {
			if file || fields[name] {
				return payload, nil, fmt.Errorf("文本字段 %s 不得作为文件或重复提交", name)
			}
			if raw := part.Header.Get("Content-Type"); raw != "" {
				kind, parameters, err := mime.ParseMediaType(raw)
				if err != nil || kind != "text/plain" || (parameters["charset"] != "" && !strings.EqualFold(parameters["charset"], "utf-8")) {
					return payload, nil, fmt.Errorf("multipart 文本必须使用 UTF-8 纯文本")
				}
			}
		}
		fields[name] = true
		data, err := io.ReadAll(part)
		if err != nil {
			return payload, nil, fmt.Errorf("multipart 字段读取失败: %w", err)
		}
		path := fmt.Sprintf("/parts/%d", len(parts))
		description := map[string]any{"name": name}
		payload.Texts = append(payload.Texts, security.Text{Path: path + "/name", Value: name})
		headers := make(map[string]any)
		for key, values := range part.Header {
			headerPath := path + "/headers/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
			payload.Texts = append(payload.Texts, security.Text{Path: headerPath, Value: key})
			items := make([]any, 0, len(values))
			for index, value := range values {
				if !utf8.ValidString(value) {
					return payload, nil, fmt.Errorf("multipart 字段头包含非法 UTF-8")
				}
				items = append(items, value)
				payload.Texts = append(payload.Texts, security.Text{Path: fmt.Sprintf("%s/%d", headerPath, index), Value: value})
			}
			headers[key] = items
		}
		description["headers"] = headers
		if file {
			description["filename"] = filename
			description["size"] = len(data)
			description["sha256"] = fmt.Sprintf("%x", sha256.Sum256(data))
			payload.Texts = append(payload.Texts, security.Text{Path: path + "/filename", Value: filename})
		} else {
			if !utf8.Valid(data) || (name == "prompt" && strings.TrimSpace(string(data)) == "") {
				return payload, nil, fmt.Errorf("multipart 文本字段无效")
			}
			if name == "stream" {
				if string(data) != "true" && string(data) != "false" {
					return payload, nil, fmt.Errorf("stream 必须为 true 或 false")
				}
			}
			description["value"] = string(data)
			payload.Texts = append(payload.Texts, security.Text{Path: path + "/value", Value: string(data), Maskable: name == "prompt"})
		}
		descriptions = append(descriptions, description)
		parts = append(parts, imageEditPart{header: part.Header, data: data, file: file})
	}
	if !fields["prompt"] || images == 0 {
		return payload, nil, fmt.Errorf("图片编辑需要 prompt 和至少一张图片")
	}
	payload.Root = map[string]any{"format": "multipart/form-data", "parts": descriptions}
	marshal := func(payload security.Payload) ([]byte, error) {
		var buffer bytes.Buffer
		writer := multipart.NewWriter(&buffer)
		if err := writer.SetBoundary(boundary); err != nil {
			return nil, err
		}
		for index, part := range parts {
			data := part.data
			header := part.header
			if !part.file {
				value := payload.Root.(map[string]any)["parts"].([]any)[index].(map[string]any)["value"].(string)
				// 保持原 boundary；拒绝替换文本注入新的 multipart 字段。
				if strings.HasPrefix(value, "--"+boundary) || strings.Contains(value, "\n--"+boundary) {
					return nil, fmt.Errorf("脱敏文本与 multipart 分隔符冲突")
				}
				data = []byte(value)
				if !bytes.Equal(data, part.data) {
					// 文本变化后，字段级长度和摘要同样失效；文件字段仍保留原头。
					header = make(textproto.MIMEHeader, len(part.header))
					for key, values := range part.header {
						header[key] = append([]string(nil), values...)
					}
					for _, name := range []string{"Content-Length", "Content-MD5", "Digest", "Etag", "Content-Digest", "Repr-Digest"} {
						header.Del(name)
					}
				}
			}
			output, err := writer.CreatePart(header)
			if err != nil {
				return nil, err
			}
			if _, err := output.Write(data); err != nil {
				return nil, err
			}
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		return buffer.Bytes(), nil
	}
	return payload, marshal, nil
}
