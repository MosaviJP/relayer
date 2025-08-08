package relayer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/MosaviJP/eventstore"
	"github.com/fasthttp/websocket"
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

	// Check for disappearing message and handle it
	if isDisappearingMessage(evt) {
		if err := s.handleDisappearingMessage(ctx, evt); err != nil {
			s.Log.Errorf("failed to handle disappearing message %s: %v", evt.ID, err)
		} else {
			s.Log.Infof("successfully processed disappearing message %s", evt.ID)
		}
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

		// notifyListeners(&evt)
		// ws.WriteJSON(nostr.OKEnvelope{EventID: evt.ID, OK: true})
		// return ""
	}

	if ctx == nil {
		fmt.Printf("doEvent: context is nil for event %s\n", evt.ID)
	} else if ctx.Err() != nil {
		fmt.Printf("doEvent: context error for event %s: %v\n", evt.ID, ctx.Err())
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
		println("doEvents: request has less than 2 parameters")
        ws.WriteJSON(nostr.OKEnvelope{
            EventID: "",
            OK:      false,
            Reason:  "invalid request: missing events array",
        })
        return ""
    }

    var events []nostr.Event
    if err := json.Unmarshal(request[1], &events); err != nil {
        println("doEvents: failed to decode events array: " + err.Error())
        ws.WriteJSON(nostr.OKEnvelope{
            EventID: "",
            OK:      false,
            Reason:  "failed to decode events array: " + err.Error(),
        })
        return ""
    }

	var disappearingEvents []nostr.Event
    for _, evt := range events {
        // 3.1 计算并验证 ID
        hash := sha256.Sum256(evt.Serialize())
        computedID := hex.EncodeToString(hash[:])
        if computedID != evt.ID {
			println("doEvents: invalid event id for " + evt.ID + ", computed=" + computedID)
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
			println("doEvents: failed to verify signature for " + evt.ID + ": " + err.Error())
            ws.WriteJSON(nostr.OKEnvelope{
                EventID: evt.ID,
                OK:      false,
                Reason:  "failed to verify signature: " + err.Error(),
            })
            return ""
        } else if !sigOK {
			println("doEvents: invalid signature for " + evt.ID)
            ws.WriteJSON(nostr.OKEnvelope{
                EventID: evt.ID,
                OK:      false,
                Reason:  "invalid signature",
            })
            return ""
        }

        accept, why := s.relay.AcceptEvent(ctx, &evt)
        if !accept {
			println("doEvents: event rejected by relay: " + why)
            ws.WriteJSON(nostr.OKEnvelope{
                EventID: evt.ID,
                OK:      false,
                Reason:  "rejected by relay: " + why,
            })
            return ""
        }
		if isDisappearingMessage(evt) {
			disappearingEvents = append(disappearingEvents, evt)
		}
    }

	if len(disappearingEvents) > 0 {
		err := s.handleDisappearingMessageList(ctx, disappearingEvents)
		if err != nil {
			println("doEvents: failed to handle disappearing messages: " + err.Error())
		}
	}

	accepted, reason := AddEvents(ctx, s.relay, events)

    for _, evt := range events {
        if !accepted{
            ws.WriteJSON(nostr.OKEnvelope{
                EventID: evt.ID,
                OK:      accepted,
                Reason:  fmt.Sprintf("failed to add event: %s", reason),
            })
        } else {
			ws.WriteJSON(nostr.OKEnvelope{EventID: evt.ID, OK: true})
		}
    }
	
	if !accepted {
		s.Log.Infof("doEvents: batch failed: %s", reason)
		ws.WriteJSON(nostr.OKEnvelope{
			EventID: "",
			OK:      false,
			Reason:  fmt.Sprintf("batch failed: %s", reason),
		})
		return ""
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
			if ctx == nil {
				fmt.Printf("doReq: context is nil for filter %d\n", idx)
			} else if ctx.Err() != nil {
				fmt.Printf("doReq: context error for filter %d: %v\n", idx, ctx.Err())
			}
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

func (s *Server) HandleHttpReq(w http.ResponseWriter, req *http.Request, store eventstore.Store) {
    // 设置请求超时
    ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
    defer cancel()
    
    // 尝试从请求头中获取用户 pubkey 并添加到 context
    if userPubkey := req.Header.Get("pubkey"); userPubkey != "" {
        ctx = context.WithValue(ctx, "userPubkey", userPubkey)
        s.Log.Infof("HTTP request with user pubkey: %s", userPubkey)
    }
    
    // 统一的错误响应函数
    sendErrorResponse := func(errorMsg string, httpStatus int) {
        response := QueryResponse{
            Code: -1,  // 错误状态码
            Msg:  errorMsg,
            Data: make([]*nostr.Event, 0),  // 确保是空数组而不是 nil
        }
        
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        w.Header().Set("Cache-Control", "no-cache")
        w.WriteHeader(httpStatus)
        
        if err := json.NewEncoder(w).Encode(response); err != nil {
            s.Log.Errorf("failed to encode error response: %v", err)
            // 最后的兜底，直接写入简单的错误 JSON
            w.Write([]byte(`{"code":-1,"msg":"internal error: failed to serialize error response","data":[]}`))
        }
        s.Log.Errorf("HTTP request failed: %s", errorMsg)
    }
    
    if store == nil {
        sendErrorResponse("no store available", http.StatusInternalServerError)
        return
    }

    var reqBody struct {
        Filters []json.RawMessage `json:"filters"`
    }
    if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
        sendErrorResponse("invalid request body: "+err.Error(), http.StatusBadRequest)
        return
    }

    // 解析 filters 并检查 limit 逻辑（参考 doReq）
    filters := make(nostr.Filters, len(reqBody.Filters))
    limitZeroFlags := make([]bool, len(filters))

    for i, filterReq := range reqBody.Filters {
        var raw map[string]json.RawMessage
        if err := json.Unmarshal(filterReq, &raw); err != nil {
            sendErrorResponse("failed to decode filter: "+err.Error(), http.StatusBadRequest)
            return
        }
        if v, ok := raw["limit"]; ok {
            var lim int
            if err := json.Unmarshal(v, &lim); err == nil && lim == 0 {
                limitZeroFlags[i] = true
            }
        }

        if err := json.Unmarshal(filterReq, &filters[i]); err != nil {
            sendErrorResponse("failed to decode filter: "+err.Error(), http.StatusBadRequest)
            return
        }
    }

    // 收集所有事件到内存中（非流式）
    var allEvents []*nostr.Event = make([]*nostr.Event, 0)  // 确保初始化为空切片而不是 nil
    totalEventCount := 0
    const MAX_EVENTS = 100000
    
    // 处理每个 filter（参考 doReq 的逻辑）
filterLoop:
    for idx, filter := range filters {
        // 检查上下文是否已取消
        select {
        case <-ctx.Done():
            s.Log.Warningf("request timeout at filter %d", idx)
            break filterLoop
        default:
        }
        
        // 如果 limit 为 0，跳过此 filter（参考 doReq）
        if limitZeroFlags[idx] {
            continue
        }
        
        // 应用与 doReq 相同的 limit 逻辑
        if filter.Limit == 0 {
            filter.Limit = 1000  // 进一步降低默认值到 1000
        }
        
        // 限制单个 filter 最大 1000 条
        if filter.Limit > 1000 {
            filter.Limit = 1000
        }
        
        events, err := store.QueryEvents(ctx, filter)
        if err != nil {
            s.Log.Errorf("query error for filter %d: %v", idx, err)
            continue
        }

        var filterEvents []*nostr.Event
        filterEventCount := 0
        for ev := range events {
            // 检查上下文
            select {
            case <-ctx.Done():
                s.Log.Warningf("request timeout while processing events")
                // 耗尽剩余的 channel
                for range events {
                }
                break filterLoop
            default:
            }
            
            if s.options.skipEventFunc != nil && s.options.skipEventFunc(ev) {
                continue
            }
            
            // 检查单个 filter 的 limit
            if filterEventCount >= filter.Limit {
                // 耗尽剩余的 channel
                for range events {
                }
                break
            }
            
            // 检查总数限制
            if totalEventCount >= MAX_EVENTS {
                s.Log.Infof("reached max events limit (%d), stopping", MAX_EVENTS)
                // 耗尽剩余的 channel
                for range events {
                }
                break filterLoop
            }
            
            filterEvents = append(filterEvents, ev)
            filterEventCount++
            totalEventCount++
        }
        
        // 耗尽 channel 确保清理
        for range events {
        }
        
        allEvents = append(allEvents, filterEvents...)
        
        // 检查是否应该停止
        if totalEventCount >= MAX_EVENTS {
            break filterLoop
        }
    }

    // 设置适当的头部
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    w.Header().Set("Cache-Control", "no-cache")
    
    // 预先序列化响应以检查大小和有效性
    // 确保 allEvents 不是 nil，即使为空也要是空切片
    if allEvents == nil {
        allEvents = make([]*nostr.Event, 0)
    }
    
    response := QueryResponse{
        Code: 0,
        Msg:  fmt.Sprintf("getSessionKeysSuccess (%d events)", len(allEvents)),
        Data: allEvents,
    }
    
    responseBytes, err := json.Marshal(response)
    if err != nil {
        s.Log.Errorf("failed to marshal response: %v", err)
        sendErrorResponse("failed to serialize response: "+err.Error(), http.StatusInternalServerError)
        return
    }
    
    // 检查响应大小，如果太大则分批返回
    const MAX_RESPONSE_SIZE = 5 * 1024 * 1024  // 降低到 5MB 限制
    if len(responseBytes) > MAX_RESPONSE_SIZE {
        s.Log.Warningf("response too large: %d bytes, truncating to first events", len(responseBytes))
        
        // 如果响应太大，逐步减少事件数量直到响应大小合适
        maxEvents := len(allEvents) / 2
        for maxEvents > 100 && len(responseBytes) > MAX_RESPONSE_SIZE {
            truncatedResponse := QueryResponse{
                Code: 0,
                Msg:  fmt.Sprintf("getSessionKeysSuccess (%d events, truncated from %d)", maxEvents, len(allEvents)),
                Data: allEvents[:maxEvents],
            }
            responseBytes, err = json.Marshal(truncatedResponse)
            if err != nil {
                s.Log.Errorf("failed to marshal truncated response: %v", err)
                sendErrorResponse("failed to serialize truncated response: "+err.Error(), http.StatusInternalServerError)
                return
            }
            maxEvents = maxEvents / 2
        }
        
        if len(responseBytes) > MAX_RESPONSE_SIZE {
            s.Log.Errorf("unable to reduce response size below limit")
            sendErrorResponse("response too large, unable to reduce size", http.StatusRequestEntityTooLarge)
            return
        }
    }
    
    s.Log.Infof("sending response: %d events, %d bytes", len(allEvents), len(responseBytes))
    
    // 设置 Content-Length 头部
    w.Header().Set("Content-Length", fmt.Sprintf("%d", len(responseBytes)))
    
    // 分块写入大响应，避免 I/O 超时
    const CHUNK_SIZE = 16 * 1024  // 减小到 16KB 每块
    totalWritten := 0
    
    // 设置更长的写入超时（如果支持的话）
    if conn, ok := w.(interface{ SetWriteDeadline(time.Time) error }); ok {
        conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
    }
    
    for totalWritten < len(responseBytes) {
        // 检查连接是否还活着
        select {
        case <-ctx.Done():
            s.Log.Warningf("client disconnected during response writing at %d/%d bytes", totalWritten, len(responseBytes))
            return
        default:
        }
        
        end := totalWritten + CHUNK_SIZE
        if end > len(responseBytes) {
            end = len(responseBytes)
        }
        
        chunkSize := end - totalWritten
        // s.Log.Infof("writing chunk %d-%d (%d bytes)", totalWritten, end, chunkSize)
        
        written, err := w.Write(responseBytes[totalWritten:end])
        if err != nil {
            s.Log.Errorf("failed to write response chunk at offset %d (chunk size %d): %v", totalWritten, chunkSize, err)
            // 写入失败时，我们已经开始发送响应了，无法再发送错误响应
            // 只能记录错误并返回，客户端会收到不完整的响应
            return
        }
        
        totalWritten += written
        
        // 强制 flush 确保数据发送
        if flusher, ok := w.(http.Flusher); ok {
            flusher.Flush()
        }
        
        // 更长的休息时间，让网络有时间处理
        if totalWritten < len(responseBytes) {
            time.Sleep(5 * time.Millisecond)
        }
    }
    
    s.Log.Infof("HTTP query completed successfully: %d events, %d bytes written", len(allEvents), totalWritten)
}
func (s *Server) handleMessage(ctx context.Context, ws *WebSocket, message []byte, defaultStore eventstore.Store) {
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

	var store = defaultStore
	if typ == "REQ" || typ == "COUNT" {
		if reader := s.relay.ReaderStorage(ctx); reader != nil {
			store = reader
		}
	}

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
	s.Log.Infof("length of websocket clients: %d", len(s.clients))
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

	// 创建基础 context
	ctx, cancel := context.WithCancel(context.Background())
	
	// 尝试从请求头中获取用户 pubkey 并添加到 context
	if userPubkey := r.Header.Get("pubkey"); userPubkey != "" {
		ctx = context.WithValue(ctx, "userPubkey", userPubkey)
		s.Log.Infof("WebSocket connection with user pubkey: %s", userPubkey)
	}

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
