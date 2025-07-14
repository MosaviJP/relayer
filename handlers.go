package relayer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/fasthttp/websocket"
	"github.com/fiatjaf/eventstore"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip11"
	"github.com/nbd-wtf/go-nostr/nip42"
	"golang.org/x/time/rate"
)

// TODO: consider moving these to Server as config params
const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = pongWait / 2

	// Maximum message size allowed from peer.
	maxMessageSize = 512000
)

// TODO: consider moving these to Server as config params
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func challenge(conn *websocket.Conn) *WebSocket {
	// NIP-42 challenge
	challenge := make([]byte, 8)
	rand.Read(challenge)

	return &WebSocket{
		conn:      conn,
		challenge: hex.EncodeToString(challenge),
	}
}

func (s *Server) doEvent(ctx context.Context, ws *WebSocket, request []json.RawMessage, store eventstore.Store) string {
	advancedDeleter, _ := store.(AdvancedDeleter)
	latestIndex := len(request) - 1

	// it's a new event
	var evt nostr.Event
	if err := json.Unmarshal(request[latestIndex], &evt); err != nil {
		return "failed to decode event: " + err.Error()
	}

	// check id
	hash := sha256.Sum256(evt.Serialize())
	if id := hex.EncodeToString(hash[:]); id != evt.ID {
		reason := "invalid: event id is computed incorrectly"
		ws.WriteJSON(nostr.OKEnvelope{EventID: evt.ID, OK: false, Reason: reason})
		return ""
	}

	// check signature
	if ok, err := evt.CheckSignature(); err != nil {
		ws.WriteJSON(nostr.OKEnvelope{EventID: evt.ID, OK: false, Reason: "error: failed to verify signature"})
		return ""
	} else if !ok {
		ws.WriteJSON(nostr.OKEnvelope{EventID: evt.ID, OK: false, Reason: "invalid: signature is invalid"})
		return ""
	}

	if evt.Kind == 5 {
		// event deletion -- nip09
		for _, tag := range evt.Tags {
			if len(tag) >= 2 && tag[0] == "e" {
				ctx, cancel := context.WithTimeout(ctx, time.Millisecond*200)
				defer cancel()

				// fetch event to be deleted
				res, err := s.relay.Storage(ctx).QueryEvents(ctx, nostr.Filter{IDs: []string{tag[1]}})
				if err != nil {
					ws.WriteJSON(nostr.OKEnvelope{EventID: evt.ID, OK: false, Reason: "failed to query for target event"})
					return ""
				}

				var target *nostr.Event
				exists := false
				select {
				case target, exists = <-res:
				case <-ctx.Done():
				}
				if !exists {
					// this will happen if event is not in the database
					// or when when the query is taking too long, so we just give up
					continue
				}

				// check if this can be deleted
				if target.PubKey != evt.PubKey {
					ws.WriteJSON(nostr.OKEnvelope{EventID: evt.ID, OK: false, Reason: "insufficient permissions"})
					return ""
				}

				if advancedDeleter != nil {
					advancedDeleter.BeforeDelete(ctx, tag[1], evt.PubKey)
				}

				if err := store.DeleteEvent(ctx, target); err != nil {
					ws.WriteJSON(nostr.OKEnvelope{EventID: evt.ID, OK: false, Reason: fmt.Sprintf("error: %s", err.Error())})
					return ""
				}

				if advancedDeleter != nil {
					advancedDeleter.AfterDelete(tag[1], evt.PubKey)
				}
			}
		}

		notifyListeners(&evt)
		ws.WriteJSON(nostr.OKEnvelope{EventID: evt.ID, OK: true})
		return ""
	}

	ok, reason := AddEvent(ctx, s.relay, &evt)
	ws.WriteJSON(nostr.OKEnvelope{EventID: evt.ID, OK: ok, Reason: reason})
	return ""
}

func (s *Server) doEvents(
    ctx context.Context,
    ws *WebSocket,
    request []json.RawMessage,
    store eventstore.Store,
) string {
    if len(request) < 2 {
        ws.WriteJSON(nostr.OKEnvelope{
            EventID: "",
            OK:      false,
            Reason:  "invalid request: missing events array",
        })
        return ""
    }

    var events []nostr.Event
    if err := json.Unmarshal(request[1], &events); err != nil {
        ws.WriteJSON(nostr.OKEnvelope{
            EventID: "",
            OK:      false,
            Reason:  "failed to decode events array: " + err.Error(),
        })
        return ""
    }

    for _, evt := range events {
        // 3.1 计算并验证 ID
        hash := sha256.Sum256(evt.Serialize())
        computedID := hex.EncodeToString(hash[:])
        if computedID != evt.ID {
            ws.WriteJSON(nostr.OKEnvelope{
                EventID: "",
                OK:      false,
                Reason:  fmt.Sprintf("invalid event id for %s, computed=%s", evt.ID, computedID),
            })
            return ""
        }

        // 3.2 验签
        sigOK, err := evt.CheckSignature()
        if err != nil {
            ws.WriteJSON(nostr.OKEnvelope{
                EventID: evt.ID,
                OK:      false,
                Reason:  "failed to verify signature: " + err.Error(),
            })
            return ""
        } else if !sigOK {
            ws.WriteJSON(nostr.OKEnvelope{
                EventID: evt.ID,
                OK:      false,
                Reason:  "invalid signature",
            })
            return ""
        }

        accept, why := s.relay.AcceptEvent(ctx, &evt)
        if !accept {
            ws.WriteJSON(nostr.OKEnvelope{
                EventID: evt.ID,
                OK:      false,
                Reason:  "rejected by relay: " + why,
            })
            return ""
        }
    }

    for _, evt := range events {
        ok, reason := AddEvent(ctx, s.relay, &evt)
        if !ok {
            ws.WriteJSON(nostr.OKEnvelope{
                EventID: evt.ID,
                OK:      false,
                Reason:  fmt.Sprintf("failed to add event: %s", reason),
            })
        } else {
			ws.WriteJSON(nostr.OKEnvelope{EventID: evt.ID, OK: true})
		}
    }

    ws.WriteJSON(nostr.OKEnvelope{
        EventID: "",
        OK:      true,
        Reason:  "batch processed",
    })

    return ""
}

func (s *Server) doCount(ctx context.Context, ws *WebSocket, request []json.RawMessage, store eventstore.Store) string {
	counter, ok := store.(EventCounter)
	if !ok {
		return "restricted: this relay does not support NIP-45"
	}

	var id string
	json.Unmarshal(request[1], &id)
	if id == "" {
		return "COUNT has no <id>"
	}

	total := int64(0)
	filters := make(nostr.Filters, len(request)-2)
	for i, filterReq := range request[2:] {
		if err := json.Unmarshal(filterReq, &filters[i]); err != nil {
			return "failed to decode filter"
		}

		filter := filters[i]

		count, err := counter.CountEvents(ctx, filter)
		if err != nil {
			s.Log.Errorf("store: %v", err)
			continue
		}
		total += count
	}

	ws.WriteJSON([]interface{}{"COUNT", id, map[string]int64{"count": total}})
	return ""
}

func (s *Server) doReq(ctx context.Context, ws *WebSocket, request []json.RawMessage, store eventstore.Store) string {
	startTime := time.Now()
	
	var id string
	json.Unmarshal(request[1], &id)
	if id == "" {
		return "REQ has no <id>"
	}

	filters := make(nostr.Filters, len(request)-2)
	limitZeroFlags := make([]bool, len(filters))

	for i, filterReq := range request[2:] {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(filterReq, &raw); err != nil {
			return "failed to decode filter"
		}
		if v, ok := raw["limit"]; ok {
			var lim int
			if err := json.Unmarshal(v, &lim); err == nil && lim == 0 {
				limitZeroFlags[i] = true
			}
		}

		if err := json.Unmarshal(filterReq, &filters[i]); err != nil {
			return "failed to decode filter"
		}
	}

	if accepter, ok := s.relay.(ReqAccepter); ok {
		if !accepter.AcceptReq(ctx, id, filters, ws.authed) {
			return "REQ filters are not accepted"
		}
	}

	// 并行查询结果结构
	type filterResult struct {
		idx         int
		events      <-chan *nostr.Event
		err         error
		filterTime  time.Duration
		dbQueryTime time.Duration
		eventCount  int
	}

	// 启动并行查询
	var wg sync.WaitGroup
	results := make([]filterResult, len(filters))
	
	for idx, filter := range filters {
		if limitZeroFlags[idx] {
			results[idx] = filterResult{
				idx:         idx,
				events:      nil,
				err:         nil,
				filterTime:  0,
				dbQueryTime: 0,
				eventCount:  0,
			}
			continue
		}

		wg.Add(1)
		go func(idx int, filter nostr.Filter) {
			defer wg.Done()
			
			dbStart := time.Now()
			events, err := store.QueryEvents(ctx, filter)
			dbDuration := time.Since(dbStart)
			
			results[idx] = filterResult{
				idx:         idx,
				events:      events,
				err:         err,
				filterTime:  0, // 将在处理完事件后设置
				dbQueryTime: dbDuration,
				eventCount:  0, // 将在处理事件时计算
			}
		}(idx, filter)
	}

	// 等待所有查询完成
	wg.Wait()
	
	totalEvents := 0
	totalDbTime := time.Duration(0)

	// 按顺序处理结果，确保事件发送顺序
	for idx, result := range results {
		if limitZeroFlags[idx] {
			continue
		}

		eventProcessStart := time.Now()
		
		if result.err != nil {
			s.Log.Errorf("store: %v", result.err)
			results[idx].filterTime = time.Since(eventProcessStart)
			continue
		}

		// 确保客户端不会被事件轰炸，以防 Storage 没有正确执行 limits
		filter := filters[idx]
		if filter.Limit == 0 {
			filter.Limit = 9999999999
		}
		
		eventCount := 0
		if result.events != nil {
			for event := range result.events {
				if s.options.skipEventFunc != nil && s.options.skipEventFunc(event) {
					continue
				}
				if eventCount >= filter.Limit {
					break
				}
				ws.WriteJSON(nostr.EventEnvelope{SubscriptionID: &id, Event: *event})
				eventCount++
			}

			// 耗尽 channel（以防我们提前跳出），这样存储层会关闭它
			for range result.events {
			}
		}
		
		results[idx].eventCount = eventCount
		results[idx].filterTime = time.Since(eventProcessStart) + result.dbQueryTime
		totalEvents += eventCount
		totalDbTime += result.dbQueryTime
	}

	totalTime := time.Since(startTime)
	
	// 构建单行时间统计信息
	filterInfo := ""
	for i, result := range results {
		if i > 0 && (result.filterTime > 0 || result.dbQueryTime > 0) {
			filterInfo += ","
		}
		if result.filterTime > 0 || result.dbQueryTime > 0 {
			filterInfo += fmt.Sprintf("F%d:%v(db:%v,events:%d)", i, result.filterTime, result.dbQueryTime, result.eventCount)
		}
	}
	
	// 单行打印时间统计
	s.Log.Infof("REQ %s timing: Total:%v Filters:%d [%s] TotalDB:%v TotalEvents:%d (parallel)", 
		id, totalTime, len(filters), filterInfo, totalDbTime, totalEvents)

	ws.WriteJSON(nostr.EOSEEnvelope(id))
	setListener(id, ws, filters)
	return ""
}

func (s *Server) doClose(ctx context.Context, ws *WebSocket, request []json.RawMessage, store eventstore.Store) string {
	var id string
	json.Unmarshal(request[1], &id)
	if id == "" {
		return "CLOSE has no <id>"
	}

	removeListenerId(ws, id)
	return ""
}

func (s *Server) doAuth(ctx context.Context, ws *WebSocket, request []json.RawMessage, store eventstore.Store) string {
	if auther, ok := s.relay.(Auther); ok {
		var evt nostr.Event
		if err := json.Unmarshal(request[1], &evt); err != nil {
			return "failed to decode auth event: " + err.Error()
		}
		if pubkey, ok := nip42.ValidateAuthEvent(&evt, ws.challenge, auther.ServiceURL()); ok {
			ws.authed = pubkey
			ws.WriteJSON(nostr.OKEnvelope{EventID: evt.ID, OK: true})
		} else {
			ws.WriteJSON(nostr.OKEnvelope{EventID: evt.ID, OK: false, Reason: "error: failed to authenticate"})
		}
	}
	return ""
}

type FilterRequest struct {
	Filters nostr.Filters `json:"filters"`
}

type QueryResponse struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data []*nostr.Event  `json:"data"`
}

func (s *Server)HandleHttpReq(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	store := s.relay.Storage(ctx)
	if store == nil {
		http.Error(w, "no store available", http.StatusInternalServerError)
		return
	}

	var reqBody FilterRequest
	if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	slog.Debug("HandleHttpReq", "filters", reqBody.Filters)
	// 并发查询结果结构
	type filterResult struct {
		idx    int
		events []*nostr.Event
		err    error
	}

	// 启动并发查询
	var wg sync.WaitGroup
	results := make([]filterResult, len(reqBody.Filters))
	
	for idx, filter := range reqBody.Filters {
		wg.Add(1)
		go func(idx int, filter nostr.Filter) {
			defer wg.Done()
			
			if filter.Limit == 0 {
				filter.Limit = 99999999
			}
			
			events, err := store.QueryEvents(ctx, filter)
			if err != nil {
				results[idx] = filterResult{
					idx:    idx,
					events: nil,
					err:    err,
				}
				return
			}

			var filterEvents []*nostr.Event
			count := 0
			for ev := range events {
				if s.options.skipEventFunc != nil && s.options.skipEventFunc(ev) {
					continue
				}
				filterEvents = append(filterEvents, ev)
				count++
				if count >= filter.Limit {
					break
				}
			}
			// 耗尽 channel（以防我们提前跳出）
			for range events {
			}

			results[idx] = filterResult{
				idx:    idx,
				events: filterEvents,
				err:    nil,
			}
		}(idx, filter)
	}

	// 等待所有查询完成
	wg.Wait()
	
	// 按顺序收集结果，确保事件顺序
	var allEvents []*nostr.Event
	for _, result := range results {
		if result.err != nil {
			s.Log.Errorf("query error: %v", result.err)
			continue
		}
		allEvents = append(allEvents, result.events...)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(QueryResponse{
		Code: 0,
		Msg:  "getSessionKeysSuccess",
		Data: allEvents,
	})
}


func (s *Server) handleMessage(ctx context.Context, ws *WebSocket, message []byte, store eventstore.Store) {
	var notice string
	defer func() {
		if notice != "" {
			ws.WriteJSON(nostr.NoticeEnvelope(notice))
		}
	}()

	var request []json.RawMessage
	if err := json.Unmarshal(message, &request); err != nil {
		// stop silently
		return
	}

	if len(request) < 2 {
		notice = "request has less than 2 parameters"
		return
	}

	var typ string
	json.Unmarshal(request[0], &typ)

	ctx = context.WithValue(ctx, AUTH_CONTEXT_KEY, ws)

	switch typ {
	case "EVENT":
		notice = s.doEvent(ctx, ws, request, store)
	case "EVENTS":
		notice = s.doEvents(ctx, ws, request, store)
	case "COUNT":
		notice = s.doCount(ctx, ws, request, store)
	case "REQ":
		notice = s.doReq(ctx, ws, request, store)
	case "CLOSE":
		notice = s.doClose(ctx, ws, request, store)
	case "AUTH":
		notice = s.doAuth(ctx, ws, request, store)
	default:
		if cwh, ok := s.relay.(CustomWebSocketHandler); ok {
			cwh.HandleUnknownType(ws, typ, request)
		} else {
			notice = "unknown message type " + typ
		}
	}
}

func (s *Server) HandleWebsocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.Log.Errorf("failed to upgrade websocket: %v", err)
		return
	}
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	s.clients[conn] = struct{}{}
	ticker := time.NewTicker(pingPeriod)

	ip := conn.RemoteAddr().String()
	if realIP := r.Header.Get("X-Forwarded-For"); realIP != "" {
		ip = realIP // possible to be multiple comma separated
	} else if realIP := r.Header.Get("X-Real-Ip"); realIP != "" {
		ip = realIP
	}
	s.Log.Infof("connected from %s", ip)

	ws := challenge(conn)

	if s.options.perConnectionLimiter != nil {
		ws.limiter = rate.NewLimiter(
			s.options.perConnectionLimiter.Limit(),
			s.options.perConnectionLimiter.Burst(),
		)
	}

	ctx, cancel := context.WithCancel(context.Background())

	store := s.relay.Storage(ctx)

	// reader
	go func() {
		defer func() {
			cancel()
			ticker.Stop()
			s.clientsMu.Lock()
			if _, ok := s.clients[conn]; ok {
				conn.Close()
				delete(s.clients, conn)
				removeListener(ws)
			}
			s.clientsMu.Unlock()
			s.Log.Infof("disconnected from %s", ip)
		}()

		conn.SetReadLimit(maxMessageSize)
		conn.SetReadDeadline(time.Now().Add(pongWait))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(pongWait))
			return nil
		})

		for {
			typ, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(
					err,
					websocket.CloseGoingAway,        // 1001
					websocket.CloseNoStatusReceived, // 1005
					websocket.CloseAbnormalClosure,  // 1006
				) {
					s.Log.Warningf("unexpected close error from %s: %v", r.Header.Get("X-Forwarded-For"), err)
				}
				break
			}

			if ws.limiter != nil {
				// NOTE: Wait will throttle the requests.
				// To reject requests exceeding the limit, use if !ws.limiter.Allow()
				if err := ws.limiter.Wait(context.TODO()); err != nil {
					s.Log.Warningf("unexpected limiter error %v", err)
					continue
				}
			}

			if typ == websocket.PingMessage {
				ws.WriteMessage(websocket.PongMessage, nil)
				continue
			}

			go s.handleMessage(ctx, ws, message, store)
		}
	}()

	// writer
	go func() {
		defer func() {
			cancel()
			ticker.Stop()
			conn.Close()
		}()

		for {
			select {
			case <-ticker.C:
				err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait))
				if err != nil {
					s.Log.Errorf("error writing ping: %v; closing websocket", err)
					return
				}
				s.Log.Infof("pinging for %s", ip)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *Server) HandleNIP11(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var info nip11.RelayInformationDocument
	if ifmer, ok := s.relay.(Informationer); ok {
		info = ifmer.GetNIP11InformationDocument()
	} else {
		supportedNIPs := []any{9, 11, 12, 15, 16, 20, 33}
		if _, ok := s.relay.(Auther); ok {
			supportedNIPs = append(supportedNIPs, 42)
		}
		if storage, ok := s.relay.(eventstore.Store); ok && storage != nil {
			if _, ok = storage.(EventCounter); ok {
				supportedNIPs = append(supportedNIPs, 45)
			}
		}

		info = nip11.RelayInformationDocument{
			Name:          s.relay.Name(),
			Description:   "relay powered by the relayer framework",
			PubKey:        "~",
			Contact:       "~",
			SupportedNIPs: supportedNIPs,
			Software:      "https://github.com/fiatjaf/relayer",
			Version:       "~",
		}
	}

	json.NewEncoder(w).Encode(info)
}
