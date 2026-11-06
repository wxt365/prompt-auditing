package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type activityBody struct {
	ctx    context.Context
	ready  chan struct{}
	finish chan struct{}
}

func (b *activityBody) Read([]byte) (int, error) {
	close(b.ready)
	select {
	case <-b.finish:
		return 0, io.EOF
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	}
}
func (b *activityBody) Close() error { return nil }

func TestConcurrencyTracksRealSlotsIndependentlyOfLogs(t *testing.T) {
	h := newTestHandler(t, "https://upstream.invalid", &memoryAuditor{failAfter: -1}, nil)
	h.semaphore = make(chan struct{}, 3)
	logs := &RequestLog{}
	h.requestLog = logs
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var bodies []*activityBody
	var done []chan int
	var cancels []context.CancelFunc
	for i := 0; i < 3; i++ {
		requestCtx, requestCancel := context.WithCancel(ctx)
		defer requestCancel()
		cancels = append(cancels, requestCancel)
		body := &activityBody{ctx: requestCtx, ready: make(chan struct{}), finish: make(chan struct{})}
		bodies = append(bodies, body)
		contentType := "application/json"
		if i == 1 {
			contentType = "text/event-stream; charset=utf-8"
		}
		h.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {contentType}}, Body: body}, nil
		})
		payload := `{"input":"normal"}`
		if i == 1 {
			payload = `{"input":"normal","client_metadata":{"session_id":"same-session"}}`
		}
		request := httptest.NewRequest("POST", responsesAliasPath, strings.NewReader(payload)).WithContext(requestCtx)
		request.Header.Set("Authorization", "Bearer "+testLocalToken)
		request.Header.Set("Content-Type", "application/json")
		if i == 0 {
			request.Header.Set("session_id", "same-session")
		}
		completed := make(chan int, 1)
		done = append(done, completed)
		go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, request); completed <- w.Code }()
		select {
		case <-body.ready:
		case <-ctx.Done():
			t.Fatal("模拟上游未进入响应正文阶段")
		}
	}
	check := func() {
		t.Helper()
		snapshot := h.ConcurrencySnapshot()
		if snapshot.Current != 3 || snapshot.Limit != 3 || len(snapshot.Items) != 3 || len(snapshot.Sessions) != 2 {
			t.Fatalf("并发快照错误: %+v", snapshot)
		}
		for _, group := range snapshot.Sessions {
			if group.SessionID == "" {
				if group.Current != 1 || group.HTTP != 1 {
					t.Fatal("未识别统计错误")
				}
			} else if group.Current != 2 || group.HTTP != 1 || group.SSE != 1 {
				t.Fatal("同一 Session 未合并或协议计数错误")
			}
		}
		for _, item := range snapshot.Items {
			if item.Phase != "responding" || item.Path != responsesAliasPath {
				t.Fatal("阶段或客户端原路径错误")
			}
		}
		encoded, _ := json.Marshal(snapshot)
		for _, secret := range []string{"same-session", testLocalToken, "upstream-key", `"input"`} {
			if strings.Contains(string(encoded), secret) {
				t.Fatal("并发统计泄露原始请求数据")
			}
		}
		snapshot.Items[0].Phase = "changed"
		if h.ConcurrencySnapshot().Items[0].Phase == "changed" {
			t.Fatal("快照修改影响实际状态")
		}
	}
	check()
	w := performRequest(h, []byte(`{"input":"normal"}`), "")
	if w.Code != 429 {
		t.Fatal("满额请求未拒绝")
	}
	check()
	logs.SetEnabled(true)
	for i := 0; i < requestLogCapacity+1; i++ {
		logs.begin("test", "POST", responsesPath)
	}
	logs.Clear()
	logs.SetEnabled(false)
	check()
	// 并行查询期间释放与取消请求，检验快照与生命周期间的数据竞争。
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 100; j++ {
				h.ConcurrencySnapshot()
			}
		}()
	}
	close(bodies[0].finish)
	cancels[1]()
	close(bodies[2].finish)
	for _, completed := range done {
		select {
		case status := <-completed:
			if status != 200 {
				t.Fatal(status)
			}
		case <-ctx.Done():
			t.Fatal("请求未释放")
		}
	}
	readers.Wait()
	if snapshot := h.ConcurrencySnapshot(); snapshot.Current != 0 || len(snapshot.Sessions) != 0 || len(h.semaphore) != 0 {
		t.Fatalf("请求结束后名额未释放: %+v", snapshot)
	}
}

func TestConcurrencySessionIdentityBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, first, second string
		known               bool
	}{
		{"相同标识", "session-a", "session-a", true},
		{"冲突标识", "session-a", "session-b", false},
		{"无效字符", "session-a", "<script>", false},
		{"超长标识", "session-a", strings.Repeat("a", 257), false},
		{"空标识", "", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newTestHandler(t, "https://upstream.invalid", &memoryAuditor{failAfter: -1}, nil)
			r := httptest.NewRequest("POST", responsesPath, nil)
			r.Header.Set("session_id", test.first)
			r.Header.Set("X-Session-ID", test.second)
			if !h.acquireActivity(r, "request") {
				t.Fatal("无法获取名额")
			}
			defer h.releaseActivity()
			first := h.ConcurrencySnapshot().Items[0].SessionID
			if (first != "") != test.known {
				t.Fatal("Session 识别错误")
			}
			other := newTestHandler(t, "https://upstream.invalid", &memoryAuditor{failAfter: -1}, nil)
			other.acquireActivity(r, "other")
			defer other.releaseActivity()
			if test.known && first == other.ConcurrencySnapshot().Items[0].SessionID {
				t.Fatal("不同实例不应使用同一匿名标签")
			}
		})
	}
}

func TestConcurrencyWebSocketEventsShareOneSlot(t *testing.T) {
	upstream, _, _ := webSocketTestUpstream(t, false)
	h := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)
	conn, ctx := dialWebSocketGateway(t, h, responsesAliasPath, testLocalToken)
	for i, session := range []string{"session-a", "session-a", "session-b"} {
		body := []byte(`{"type":"response.create","response":{"input":"normal","client_metadata":{"session_id":"` + session + `"}}}`)
		if err := conn.Write(ctx, websocket.MessageText, body); err != nil {
			t.Fatal(err)
		}
		webSocketRead(t, ctx, conn)
		snapshot := h.ConcurrencySnapshot()
		if snapshot.Current != 1 || len(snapshot.Sessions) != 1 || snapshot.Sessions[0].WebSocket != 1 || snapshot.Items[0].Phase != "responding" {
			t.Fatalf("事件不能重复占用名额或覆盖连接状态: %+v", snapshot)
		}
		if (snapshot.Items[0].SessionID != "") != (i < 2) {
			t.Fatal("复用连接的 Session 归属错误")
		}
	}
	conn.CloseNow()
	h.CloseWebSockets()
	deadline := time.Now().Add(3 * time.Second)
	for h.ConcurrencySnapshot().Current != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.ConcurrencySnapshot().Current != 0 {
		t.Fatal("WebSocket 断开后未释放名额")
	}
}
