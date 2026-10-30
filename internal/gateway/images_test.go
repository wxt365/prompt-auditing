package gateway

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

var imageRules = []storage.Rule{
	{ID: "block-image", Type: "keyword", Action: "block", Enabled: true, Keywords: []string{"客户A"}},
	{ID: "mask-image", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "内部系统A", Target: "业务系统"}}},
}

func imageRequest(handler http.Handler, path, contentType string, body []byte, token, encoding string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if encoding != "" {
		r.Header.Set("Content-Encoding", encoding)
	}
	for _, name := range []string{"Content-MD5", "Digest", "Etag", "Content-Digest", "Repr-Digest"} {
		r.Header.Set(name, "old-integrity")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestImageJSONGatewayRoutesAuthMaskAndStreaming(t *testing.T) {
	for _, clientAuth := range []bool{false, true} {
		for _, base := range []string{"", "/v1", "/v1/", "/proxy/v1/", "/proxy/"} {
			for _, path := range []string{imagesGenerationsPath, imagesEditsPath} {
				t.Run(fmt.Sprintf("%t%s%s", clientAuth, base, path), func(t *testing.T) {
					var calls atomic.Int32
					const sse = "event: image_generation.completed\ndata: {\"b64_json\":\"abc\"}\n\n"
					const normal = `{"data":[{"b64_json":"abc"}]}`
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						if r.URL.Path != strings.TrimRight(base, "/")+path {
							t.Errorf("上游路径=%s", r.URL.Path)
						}
						body, _ := io.ReadAll(r.Body)
						var object map[string]any
						if err := json.Unmarshal(body, &object); err != nil || object["prompt"] != "业务系统" || object["model"] != "gpt-test" {
							t.Errorf("上游 JSON 错误: %s %v", body, err)
						}
						expectedAuth := "Bearer upstream-key"
						if clientAuth {
							expectedAuth = "Bearer client-key"
						}
						if r.Header.Get("Authorization") != expectedAuth || r.Header.Get("Digest") != "" {
							t.Error("认证或正文完整性 Header 错误")
						}
						if object["stream"] == true {
							w.Header().Set("Content-Type", "text/event-stream")
							_, _ = io.WriteString(w, sse)
						} else {
							w.Header().Set("Content-Type", "application/json")
							_, _ = io.WriteString(w, normal)
						}
					}))
					defer upstream.Close()
					auditor := &memoryAuditor{failAfter: -1}
					handler := newTestHandler(t, upstream.URL+base, auditor, imageRules)
					token := testLocalToken
					if clientAuth {
						handler = newClientAuthHandler(t, upstream.URL+base, auditor, imageRules)
						token = "client-key"
					}
					handler.requestLog = &RequestLog{}
					handler.requestLog.SetEnabled(true)
					suffix := ""
					if path == imagesEditsPath {
						suffix = `,"images":[{"file_id":"file-1"}]`
					}
					for _, blocked := range []string{
						`{"prompt":"客户A"` + suffix + `}`,
						`{"prompt":"ok","metadata":{"客户A":"value"}` + suffix + `}`,
						`{"prompt":"ok","model":"内部系统A"` + suffix + `}`,
					} {
						response := imageRequest(handler, path, "application/json", []byte(blocked), token, "")
						if response.Code != http.StatusForbidden || calls.Load() != 0 {
							t.Fatalf("阻断失败: %d %s", response.Code, response.Body.String())
						}
					}
					for _, stream := range []bool{true, false} {
						body := []byte(fmt.Sprintf(`{"prompt":"内部系统A","model":"gpt-test","stream":%t%s}`, stream, suffix))
						response := imageRequest(handler, path, "application/json", body, token, "")
						expected := normal
						if stream {
							expected = sse
						}
						if response.Code != http.StatusOK || response.Body.String() != expected {
							t.Fatalf("响应透传失败: %d %s", response.Code, response.Body.String())
						}
					}
					if calls.Load() != 2 || len(auditor.events) != 7 || len(auditor.events[0].RequestBody) == 0 {
						t.Fatalf("转发或审计数量错误: calls=%d events=%d", calls.Load(), len(auditor.events))
					}
					for _, entry := range handler.requestLog.Snapshot().Items {
						if entry.Path != path || !entry.Finished {
							t.Fatalf("图片路径未记录: %+v", entry)
						}
					}
				})
			}
		}
	}
}

type testImagePart struct {
	name, filename string
	data           []byte
	header         textproto.MIMEHeader
}

func imageMultipart(t *testing.T, parts ...testImagePart) ([]byte, string) {
	t.Helper()
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	if err := writer.SetBoundary("gateway-test-boundary"); err != nil {
		t.Fatal(err)
	}
	for _, part := range parts {
		header := make(textproto.MIMEHeader)
		params := map[string]string{"name": part.name}
		if part.filename != "" {
			params["filename"] = part.filename
			header.Set("Content-Type", "image/png")
		}
		header.Set("Content-Disposition", mime.FormatMediaType("form-data", params))
		for name, values := range part.header {
			header[name] = values
		}
		output, err := writer.CreatePart(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := output.Write(part.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes(), writer.FormDataContentType()
}

func TestImageMultipartMaskPreservesFilesAndIntegrity(t *testing.T) {
	for _, mask := range []bool{false, true} {
		for _, encoding := range []string{"", "gzip"} {
			t.Run(fmt.Sprintf("mask=%t/%s", mask, encoding), func(t *testing.T) {
				image := []byte("\x89PNG\r\n\x1a\n客户A\x00\xff")
				prompt := "ordinary prompt"
				if mask {
					prompt = "内部系统A"
				}
				body, contentType := imageMultipart(t,
					testImagePart{name: "model", data: []byte("gpt-test")},
					testImagePart{name: "prompt", data: []byte(prompt), header: textproto.MIMEHeader{"Content-Length": {fmt.Sprint(len(prompt))}, "Digest": {"old-part-digest"}}},
					testImagePart{name: "stream", data: []byte("true")},
					testImagePart{name: "image[]", filename: "original.png", data: image},
					testImagePart{name: "image[]", filename: "second.png", data: image},
					testImagePart{name: "mask", filename: "mask.png", data: image},
				)
				wireBody := body
				if encoding == "gzip" {
					wireBody = gzipBody(t, body)
				}
				var calls atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					wire, _ := io.ReadAll(r.Body)
					if !mask && !bytes.Equal(wire, wireBody) {
						t.Error("未修改请求必须保留原始字节")
					}
					if r.Header.Get("Content-Type") != contentType || r.Header.Get("Content-Encoding") != encoding || r.ContentLength != int64(len(wire)) {
						t.Error("重编码后的 Header 错误")
					}
					for _, name := range []string{"Content-MD5", "Digest", "Etag", "Content-Digest", "Repr-Digest"} {
						if mask && r.Header.Get(name) != "" {
							t.Errorf("残留完整性 Header: %s", name)
						}
					}
					decoded := wire
					if encoding == "gzip" {
						reader, err := gzip.NewReader(bytes.NewReader(wire))
						if err != nil {
							t.Error(err)
							return
						}
						decoded, _ = io.ReadAll(reader)
						_ = reader.Close()
					}
					reader := multipart.NewReader(bytes.NewReader(decoded), "gateway-test-boundary")
					count := 0
					for {
						part, err := reader.NextRawPart()
						if err == io.EOF {
							break
						}
						if err != nil {
							t.Error(err)
							break
						}
						data, _ := io.ReadAll(part)
						count++
						if part.FileName() != "" && !bytes.Equal(data, image) {
							t.Error("图片字节被修改")
						}
						if part.FormName() == "prompt" {
							expected := prompt
							if mask {
								expected = "业务系统"
							}
							if string(data) != expected {
								t.Errorf("提示词=%q", data)
							}
							if mask && (part.Header.Get("Content-Length") != "" || part.Header.Get("Digest") != "") {
								t.Error("脱敏文本残留失效的字段级长度或摘要")
							}
							if !mask && part.Header.Get("Digest") != "old-part-digest" {
								t.Error("未修改字段丢失原摘要")
							}
						}
					}
					if count != 6 {
						t.Errorf("multipart 字段数量=%d", count)
					}
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "event: image_edit.completed\ndata: {}\n\n")
				}))
				defer upstream.Close()
				handler := newTestHandler(t, upstream.URL+"/v1/", &memoryAuditor{failAfter: -1}, imageRules)
				response := imageRequest(handler, imagesEditsPath, contentType, wireBody, testLocalToken, encoding)
				if response.Code != http.StatusOK || calls.Load() != 1 || response.Body.String() != "event: image_edit.completed\ndata: {}\n\n" {
					t.Fatalf("multipart 转发失败: %d %s", response.Code, response.Body.String())
				}
			})
		}
	}
}

func TestImageMultipartAuditRedactsAllMetadataCredentials(t *testing.T) {
	const credential = "multipart-client-secret"
	body, contentType := imageMultipart(t,
		testImagePart{name: "prompt", data: []byte("客户A " + credential)},
		testImagePart{name: "image", filename: credential + ".png", data: []byte("private-binary"), header: textproto.MIMEHeader{"X-Meta": {credential, "another " + credential}}},
		testImagePart{name: credential, data: []byte(credential)},
	)
	auditor := &memoryAuditor{failAfter: -1}
	handler := newClientAuthHandler(t, "http://example.invalid/v1", auditor, imageRules)
	response := imageRequest(handler, imagesEditsPath, contentType, body, credential, "")
	if response.Code != http.StatusForbidden || len(auditor.events) != 1 {
		t.Fatalf("status=%d events=%d", response.Code, len(auditor.events))
	}
	recorded, err := json.Marshal(auditor.events)
	if err != nil || bytes.Contains(recorded, []byte(credential)) || bytes.Contains(recorded, []byte("private-binary")) {
		t.Fatalf("凭证或二进制进入审计: %s %v", recorded, err)
	}
	if !bytes.Contains(recorded, []byte(redactedCredential)) {
		t.Fatal("缺少凭证脱敏标记")
	}
}

func TestImageJSONGzipAndMultipartBodyLimits(t *testing.T) {
	for _, path := range []string{imagesGenerationsPath, imagesEditsPath} {
		t.Run(path, func(t *testing.T) {
			body := []byte(`{"prompt":"内部系统A","model":"gpt-test"}`)
			if path == imagesEditsPath {
				body = []byte(`{"prompt":"内部系统A","model":"gpt-test","images":[{"file_id":"file-1"}]}`)
			}
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				reader, err := gzip.NewReader(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				decoded, err := io.ReadAll(reader)
				_ = reader.Close()
				if err != nil || !bytes.Contains(decoded, []byte("业务系统")) || bytes.Contains(decoded, []byte("内部系统A")) || r.Header.Get("Digest") != "" {
					t.Errorf("gzip 脱敏失败: %s %v", decoded, err)
				}
				_, _ = io.WriteString(w, `{"data":[]}`)
			}))
			defer upstream.Close()
			handler := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, imageRules)
			response := imageRequest(handler, path, "application/json", gzipBody(t, body), testLocalToken, "gzip")
			if response.Code != 200 || calls.Load() != 1 {
				t.Fatalf("status=%d calls=%d", response.Code, calls.Load())
			}
		})
	}
	body, contentType := imageMultipart(t, testImagePart{name: "prompt", data: []byte("ok")}, testImagePart{name: "image", filename: "i.png", data: bytes.Repeat([]byte("x"), 2048)})
	handler := newTestHandlerWithLimits(t, "http://example.invalid", &memoryAuditor{failAfter: -1}, nil, config.LimitsConfig{MaxCompressedBytes: 1024, MaxDecompressedBytes: 1024, MaxConcurrent: 1})
	for _, encoding := range []string{"", "gzip"} {
		wire := body
		if encoding == "gzip" {
			wire = gzipBody(t, body)
		}
		if response := imageRequest(handler, imagesEditsPath, contentType, wire, testLocalToken, encoding); response.Code != 413 {
			t.Fatalf("multipart %s 限额未执行: %d %s", encoding, response.Code, response.Body.String())
		}
	}
}

func TestImageMultipartAcceptsAboveOldDefaultAndRetainsConfiguredLimits(t *testing.T) {
	image := bytes.Repeat([]byte("x"), 6<<20)
	body, contentType := imageMultipart(t, testImagePart{name: "prompt", data: []byte("ok")}, testImagePart{name: "image", filename: "i.png", data: image})
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		forwarded, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(forwarded, body) {
			t.Error("大图片请求未完整原样转发", err)
		}
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	defer upstream.Close()
	cfg, err := config.Prepare(config.Config{Version: 1, Upstream: upstream.URL, PolicyDB: "policy.db", AuditDB: "audit.db"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestHandlerWithLimits(t, upstream.URL, &memoryAuditor{failAfter: -1}, imageRules, config.LimitsConfig{MaxCompressedBytes: cfg.MaxBodyBytes, MaxDecompressedBytes: cfg.MaxBodyBytes, MaxConcurrent: 1})
	response := imageRequest(handler, imagesEditsPath, contentType, body, testLocalToken, "")
	if response.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("默认限额仍拒绝 6 MiB 图片: status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
	}
	// 超过新默认限额时在读取正文之前拒绝，不分配 GiB 级测试数据。
	request := httptest.NewRequest(http.MethodPost, imagesEditsPath, nil)
	request.Header.Set("Authorization", "Bearer "+testLocalToken)
	request.Header.Set("Content-Type", contentType)
	request.ContentLength = 1073741825
	writer := httptest.NewRecorder()
	handler.ServeHTTP(writer, request)
	if writer.Code != http.StatusRequestEntityTooLarge || calls.Load() != 1 {
		t.Fatalf("超过1GiB未拒绝: status=%d calls=%d", writer.Code, calls.Load())
	}
	custom := newTestHandlerWithLimits(t, upstream.URL, &memoryAuditor{failAfter: -1}, imageRules, config.LimitsConfig{MaxCompressedBytes: 5 << 20, MaxDecompressedBytes: 5 << 20, MaxConcurrent: 1})
	response = imageRequest(custom, imagesEditsPath, contentType, body, testLocalToken, "")
	if response.Code != http.StatusRequestEntityTooLarge || calls.Load() != 1 {
		t.Fatalf("用户设置的较小限额未保留: status=%d calls=%d", response.Code, calls.Load())
	}
}

func TestImageMultipartRejectsBypassesAndAuditsMetadata(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	ordinaryImage := testImagePart{name: "image", filename: "ok.png", data: []byte("opaque-image-binary")}
	ordinaryPrompt := testImagePart{name: "prompt", data: []byte("ok")}
	for _, test := range []struct {
		name  string
		parts []testImagePart
		code  int
	}{
		{"拦截提示词", []testImagePart{{name: "prompt", data: []byte("客户A")}, ordinaryImage}, 403},
		{"模型不可替换", []testImagePart{ordinaryPrompt, ordinaryImage, {name: "model", data: []byte("内部系统A")}}, 403},
		{"动态字段名", []testImagePart{ordinaryPrompt, ordinaryImage, {name: "客户A", data: []byte("value")}}, 403},
		{"完整文件路径检测", []testImagePart{ordinaryPrompt, {name: "image", filename: "/客户A/ok.png", data: []byte("binary")}}, 403},
		{"头字段检测", []testImagePart{ordinaryPrompt, ordinaryImage, {name: "extra", data: []byte("ok"), header: textproto.MIMEHeader{"X-Note": {"客户A"}}}}, 403},
		{"缺少提示词", []testImagePart{ordinaryImage}, 422},
		{"缺少图片", []testImagePart{ordinaryPrompt}, 422},
		{"空提示词", []testImagePart{{name: "prompt", data: []byte(" ")}, ordinaryImage}, 422},
		{"重复提示词", []testImagePart{ordinaryPrompt, ordinaryPrompt, ordinaryImage}, 422},
		{"提示词伪装文件", []testImagePart{{name: "prompt", filename: "prompt.png", data: []byte("客户A")}, ordinaryImage}, 422},
		{"普通图片字段", []testImagePart{ordinaryPrompt, {name: "image", data: []byte("客户A")}}, 422},
		{"混用图片名称", []testImagePart{ordinaryPrompt, ordinaryImage, {name: "image[]", filename: "b.png"}}, 422},
		{"重复蒙版", []testImagePart{ordinaryPrompt, ordinaryImage, {name: "mask", filename: "a.png"}, {name: "mask", filename: "b.png"}}, 422},
		{"传输编码绕过", []testImagePart{{name: "prompt", data: []byte("=E5=AE=A2"), header: textproto.MIMEHeader{"Content-Transfer-Encoding": {"quoted-printable"}}}, ordinaryImage}, 422},
		{"字段压缩绕过", []testImagePart{{name: "prompt", data: []byte("opaque"), header: textproto.MIMEHeader{"Content-Encoding": {"gzip"}}}, ordinaryImage}, 422},
		{"非UTF8文本", []testImagePart{{name: "prompt", data: []byte{0xff}}, ordinaryImage}, 422},
		{"不支持图片类型", []testImagePart{ordinaryPrompt, {name: "image", filename: "i.png", header: textproto.MIMEHeader{"Content-Type": {"application/zip"}}}}, 422},
		{"重复声明头", []testImagePart{ordinaryPrompt, {name: "image", filename: "i.png", header: textproto.MIMEHeader{"Content-Disposition": {`form-data; name="image"; filename="i.png"`, `form-data; name="prompt"`}}}}, 422},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, contentType := imageMultipart(t, test.parts...)
			auditor := &memoryAuditor{failAfter: -1}
			handler := newClientAuthHandler(t, upstream.URL+"/v1", auditor, imageRules)
			response := imageRequest(handler, imagesEditsPath, contentType, body, "opaque-image-binary", "")
			if response.Code != test.code || calls.Load() != 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
			}
			if test.code == 403 {
				if len(auditor.events) != 1 || len(auditor.events[0].RequestBody) == 0 {
					t.Fatal("缺少 multipart 阻断审计")
				}
				var description map[string]any
				if err := json.Unmarshal(auditor.events[0].RequestBody, &description); err != nil || description["format"] != "multipart/form-data" {
					t.Fatalf("审计描述无效: %v", err)
				}
				if bytes.Contains(auditor.events[0].RequestBody, []byte("opaque-image-binary")) || !bytes.Contains(auditor.events[0].RequestBody, []byte("sha256")) {
					t.Fatal("文件审计应只保存摘要，不含二进制")
				}
			}
		})
	}
}

func TestImageGatewayFailsClosed(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	handler := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, imageRules)
	for _, path := range []string{"/v1/images/generations", "/v1/images/edits", "/alpha/search", imagesGenerationsPath + "?q=x"} {
		if response := imageRequest(handler, path, "application/json", []byte(`{"prompt":"ok"}`), testLocalToken, ""); response.Code != 404 {
			t.Fatalf("不应开放 %s: %d", path, response.Code)
		}
	}
	for _, path := range []string{imagesGenerationsPath, imagesEditsPath} {
		if response := imageRequest(handler, path, "application/json", []byte(`{"prompt":"ok"}`), "", ""); response.Code != 401 {
			t.Fatalf("缺少认证未拒绝: %d", response.Code)
		}
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+testLocalToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 405 {
			t.Fatalf("GET 未拒绝: %d", w.Code)
		}
	}
	body, contentType := imageMultipart(t, testImagePart{name: "prompt", data: []byte("内部系统A")}, testImagePart{name: "image", filename: "i.png", data: []byte("binary")})
	for _, test := range []struct {
		name      string
		body      []byte
		typeValue string
		code      int
	}{
		{"缺少boundary", body, "multipart/form-data", 422},
		{"截断", body[:len(body)-30], contentType, 422},
		{"生成接口不接受表单", body, "multipart/form-data; boundary=gateway-test-boundary", 415},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := imagesEditsPath
			if test.code == 415 {
				path = imagesGenerationsPath
			}
			if response := imageRequest(handler, path, test.typeValue, test.body, testLocalToken, ""); response.Code != test.code {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	// 替换结果不能注入分隔符和额外字段。
	injection := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, []storage.Rule{{ID: "inject", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "内部系统A", Target: "safe\r\n--gateway-test-boundary\r\n"}}}})
	if response := imageRequest(injection, imagesEditsPath, contentType, body, testLocalToken, ""); response.Code != 503 {
		t.Fatalf("替换分隔符注入未关闭: %d %s", response.Code, response.Body.String())
	}
	for _, blocked := range []bool{false, true} {
		auditFailure := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: 0}, imageRules)
		prompt := "内部系统A"
		if blocked {
			prompt = "客户A"
		}
		requestBody, formType := imageMultipart(t, testImagePart{name: "prompt", data: []byte(prompt)}, testImagePart{name: "image", filename: "i.png"})
		if response := imageRequest(auditFailure, imagesEditsPath, formType, requestBody, testLocalToken, ""); response.Code != 503 {
			t.Fatalf("审计故障未关闭: %d", response.Code)
		}
	}
	for _, count := range []int{17, maxImageEditParts} {
		parts := []testImagePart{{name: "prompt", data: []byte("ok")}}
		for i := 0; i < count; i++ {
			part := testImagePart{name: "image[]", filename: "i.png"}
			if count == maxImageEditParts {
				part = testImagePart{name: fmt.Sprintf("extra-%d", i), data: []byte("ok")}
			}
			parts = append(parts, part)
		}
		requestBody, formType := imageMultipart(t, parts...)
		if response := imageRequest(handler, imagesEditsPath, formType, requestBody, testLocalToken, ""); response.Code != 422 {
			t.Fatalf("字段或图片上限未执行: %d", response.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("拒绝请求到达上游")
	}
}
