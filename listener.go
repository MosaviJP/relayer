package relayer

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/nbd-wtf/go-nostr"
)

type Listener struct {
	filters nostr.Filters
}

var (
	listeners      = make(map[*WebSocket]map[string]*Listener)
	listenersMutex = sync.Mutex{}
)

func GetListeningFilters() nostr.Filters {
	respfilters := make(nostr.Filters, 0, len(listeners)*2)

	listenersMutex.Lock()
	defer listenersMutex.Unlock()

	// here we go through all the existing listeners
	for _, connlisteners := range listeners {
		for _, listener := range connlisteners {
			for _, listenerfilter := range listener.filters {
				for _, respfilter := range respfilters {
					// check if this filter specifically is already added to respfilters
					if nostr.FilterEqual(listenerfilter, respfilter) {
						goto nextconn
					}
				}

				// field not yet present on respfilters, add it
				respfilters = append(respfilters, listenerfilter)

				// continue to the next filter
			nextconn:
				continue
			}
		}
	}

	// respfilters will be a slice with all the distinct filter we currently have active
	return respfilters
}

func setListener(id string, ws *WebSocket, filters nostr.Filters) {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()

	subs, ok := listeners[ws]
	if !ok {
		subs = make(map[string]*Listener)
		listeners[ws] = subs
	}

	fmt.Printf("setting listener %s with filters %v\n", id, filters)
	subs[id] = &Listener{filters: filters}
	
	// 增加活跃listener计数
	atomic.AddInt64(&activeListeners, 1)
}

// Remove a specific subscription id from listeners for a given ws client
func removeListenerId(ws *WebSocket, id string) {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()

	if subs, ok := listeners[ws]; ok {
		delete(listeners[ws], id)
		if len(subs) == 0 {
			delete(listeners, ws)
		}
		// 减少活跃listener计数
		atomic.AddInt64(&activeListeners, -1)
	}
}

// Remove WebSocket conn from listeners
func removeListener(ws *WebSocket) {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()
	
	// 计算移除的listener数量
	if subs, ok := listeners[ws]; ok {
		removedCount := len(subs)
		atomic.AddInt64(&activeListeners, -int64(removedCount))
	}
	
	clear(listeners[ws])
	delete(listeners, ws)
}

func notifyListeners(event *nostr.Event) {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()

	// notifyListeners调用 - 只监控活跃envelope
	notifyCount := 0
	errorCount := 0
	brokenConnections := []*WebSocket{}
	listenersCount := 0
	for ws, subs := range listeners {
		for id, listener := range subs {
			listenersCount++ // 统计活跃listener数量
			if !listener.filters.Match(event) {
				continue
			}
			
			// 创建EventEnvelope时增加活跃计数
			atomic.AddInt64(&activeEventEnvelopes, 1)
			
			err := ws.WriteJSON(nostr.EventEnvelope{SubscriptionID: &id, Event: *event})
			if err != nil {
				errorCount++
				// 标记需要清理的连接，但不在这里删除避免并发问题
				brokenConnections = append(brokenConnections, ws)
				fmt.Printf("notifyListeners error for listener %s: %v\n", id, err)
				// EventEnvelope发送失败，减少活跃计数（因为WriteJSON已经不会减少了）
				atomic.AddInt64(&activeEventEnvelopes, -1)
			} else {
				notifyCount++
				// EventEnvelope成功发送，计数已经在WriteJSON中减少了
			}
		}
	}
	atomic.StoreInt64(&allListeners, int64(listenersCount))
	// 累计死连接检测计数
	if len(brokenConnections) > 0 {
		atomic.AddInt64(&deadConnections, int64(len(brokenConnections)))
	}
}
