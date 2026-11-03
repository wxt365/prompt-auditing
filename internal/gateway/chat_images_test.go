package gateway

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestChatImageGatewayForwardingRulesAndAudit(t *testing.T) {
	const image = "data:image/png;base64,YmluYXJ5"
	for _, path := range []string{chatCompletionsPath, chatCompletionsAliasPath} {
		for _, encoding := range []string{"", "gzip"} {
			for _, stream := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/stream=%t", path, encoding, stream), func(t *testing.T) {
					type forwardedRequest struct {
						body   []byte
						digest string
					}
					requests := make(chan forwardedRequest, 1)
					responseBody := `{"choices":[{"message":{"role":"assistant","content":"OK"}}]}`
					responseType := "application/json"
					if stream {
						responseBody = "data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\ndata: [DONE]\n\n"
						responseType = "text/event-stream"
					}
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer upstream-key" {
							t.Error("图片请求的上游路径、方法或认证错误")
						}
						if r.Header.Get("Content-Encoding") != encoding {
							t.Error("正文编码错误")
						}
						body, err := io.ReadAll(r.Body)
						if err != nil {
							t.Error(err)
						}
						requests <- forwardedRequest{body: body, digest: r.Header.Get("Digest")}
						w.Header().Set("Content-Type", responseType)
						_, _ = io.WriteString(w, responseBody)
					}))
					defer upstream.Close()
					auditor := &memoryAuditor{failAfter: -1}
					handler := newTestHandler(t, upstream.URL+"/v1/", auditor, []storage.Rule{
						{ID: "mask", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "内部系统A", Target: "业务系统"}}},
						{ID: "block", Type: "keyword", Action: "block", Enabled: true, Keywords: []string{"客户A", "YmluYXJ5"}},
						{ID: "warn", Type: "keyword", Action: "warn", Enabled: true, Keywords: []string{"提醒"}},
					})
					for _, test := range []struct {
						text, imagePart, action string
						status                  int
					}{
						{"正常", `{"type":"image_url","image_url":{"url":"` + image + `","detail":"original"}}`, "allow", http.StatusOK},
						{"正常", `{"type":"image_url","image_url":{"url":"https://example.com/image.png"}}`, "allow", http.StatusOK},
						{"提醒", `{"type":"image_url","image_url":{"url":"` + image + `"}}`, "warn", http.StatusOK},
						{"内部系统A", `{"type":"image_url","image_url":{"url":"` + image + `"}}`, "mask", http.StatusOK},
						{"客户A", `{"type":"image_url","image_url":{"url":"` + image + `"}}`, "block", http.StatusForbidden},
						{"正常", `{"type":"image_url","image_url":{"url":"https://example.com/客户A.png"}}`, "block", http.StatusForbidden},
						{"正常", `{"type":"image_url","image_url":{"url":"` + image + `","future":{"text":"内部系统A"}}}`, "block", http.StatusForbidden},
						{"正常", `{"type":"image_url","image_url":{"url":"data:text/plain;base64,YmluYXJ5"}}`, "block", http.StatusUnprocessableEntity},
					} {
						masked := test.action == "mask"
						body := []byte(fmt.Sprintf(`{ "model":"gpt-test", "messages":[{"role":"user","content":[{"type":"text","text":%q},%s]}], "stream":%t }`, test.text, test.imagePart, stream))
						wireBody := body
						if encoding == "gzip" {
							wireBody = gzipBody(t, body)
						}
						request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(wireBody))
						request.Header.Set("Authorization", "Bearer "+handler.localToken)
						request.Header.Set("Content-Type", "application/json")
						request.Header.Set("Digest", "stale-digest")
						if encoding != "" {
							request.Header.Set("Content-Encoding", encoding)
						}
						before := len(auditor.events)
						response := httptest.NewRecorder()
						handler.ServeHTTP(response, request)
						if response.Code != test.status {
							t.Fatalf("图片请求状态错误: action=%s status=%d body=%s", test.action, response.Code, response.Body.String())
						}
						if len(auditor.events) <= before || auditor.events[before].Action != test.action {
							t.Fatalf("图片请求审计错误: %+v", auditor.events[before:])
						}
						if test.status == http.StatusUnprocessableEntity && (auditor.events[before].EventType != "system_error" || auditor.events[before].ErrorCode != "unsupported_payload") {
							t.Fatal("无效图片结构未记录拒绝原因")
						}
						if test.status != http.StatusOK {
							if len(requests) != 0 {
								t.Fatal("拒绝的图片请求仍到达上游")
							}
							continue
						}
						if response.Body.String() != responseBody || response.Header().Get("Content-Type") != responseType || len(requests) != 1 {
							t.Fatal("图片请求的 JSON/SSE 响应未原样转发")
						}
						captured := <-requests
						forwarded := captured.body
						if masked && captured.digest != "" {
							t.Fatal("脱敏后残留失效的完整性 Header")
						}
						if !masked && !bytes.Equal(forwarded, wireBody) {
							t.Fatal("未脱敏的图片请求字节被修改")
						}
						if encoding == "gzip" {
							reader, err := gzip.NewReader(bytes.NewReader(forwarded))
							if err != nil {
								t.Fatal(err)
							}
							forwarded, err = io.ReadAll(reader)
							_ = reader.Close()
							if err != nil {
								t.Fatal(err)
							}
						}
						var expected, actual any
						if err := json.Unmarshal([]byte(strings.ReplaceAll(string(body), "内部系统A", "业务系统")), &expected); err != nil {
							t.Fatal(err)
						}
						if err := json.Unmarshal(forwarded, &actual); err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(expected, actual) {
							t.Fatalf("图片数据或协议字段被修改: %s", forwarded)
						}
					}
				})
			}
		}
	}
}
