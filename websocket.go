package relayer

import (
	"sync"
	"sync/atomic"

	"github.com/fasthttp/websocket"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/time/rate"
)

type WebSocket struct {
	conn  *websocket.Conn
	mutex sync.Mutex

	// nip42
	challenge string
	authed    string
	limiter   *rate.Limiter
}

func (ws *WebSocket) WriteJSON(any interface{}) error {
	// 监控EventEnvelope序列化（只有成功时才减少活跃计数）
	isEventEnvelope := false
	if _, ok := any.(nostr.EventEnvelope); ok {
		isEventEnvelope = true
	}
	
	ws.mutex.Lock()
	defer ws.mutex.Unlock()
	err := ws.conn.WriteJSON(any)
	
	// 只有成功发送EventEnvelope时才减少活跃计数
	if err == nil && isEventEnvelope {
		atomic.AddInt64(&activeEventEnvelopes, -1)
	}
	
	return err
}

func (ws *WebSocket) WriteMessage(t int, b []byte) error {
	ws.mutex.Lock()
	defer ws.mutex.Unlock()
	return ws.conn.WriteMessage(t, b)
}
