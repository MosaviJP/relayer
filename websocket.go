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
	// 监控EventEnvelope序列化（当成功发送时减少活跃计数）
	if _, ok := any.(nostr.EventEnvelope); ok {
		// 序列化完成，减少活跃EventEnvelope计数
		defer atomic.AddInt64(&activeEventEnvelopes, -1)
	}
	
	ws.mutex.Lock()
	defer ws.mutex.Unlock()
	err := ws.conn.WriteJSON(any)
	return err
}

func (ws *WebSocket) WriteMessage(t int, b []byte) error {
	ws.mutex.Lock()
	defer ws.mutex.Unlock()
	return ws.conn.WriteMessage(t, b)
}
