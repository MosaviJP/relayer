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

	// METRICS: 区分新增 vs 覆盖（固定 id 的情况计为 update）
	if _, existed := subs[id]; !existed {
		atomic.AddInt64(&metricReqNew, 1)
	} else {
		atomic.AddInt64(&metricReqUpdate, 1)
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
		if _, existed := subs[id]; existed {
			delete(listeners[ws], id)
			// METRICS
			atomic.AddInt64(&metricRemovedClose, 1)

			if len(subs) == 0 {
				delete(listeners, ws)
			}
			atomic.AddInt64(&activeListeners, -1)
		}
	}
}

// Remove WebSocket conn from listeners
func removeListener(ws *WebSocket) {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()
	
	// 计算移除的listener数量
	if subs, ok := listeners[ws]; ok {
		removedCount := len(subs)
		if removedCount > 0 {
			// METRICS
			atomic.AddInt64(&metricRemovedDisconnect, int64(removedCount))
			atomic.AddInt64(&activeListeners, -int64(removedCount))
		}
	}
	
	clear(listeners[ws])
	delete(listeners, ws)
}

func notifyListeners(event *nostr.Event) {
	// 在锁外准备数据，减少锁持有时间
	var targets []struct {
		ws *WebSocket
		id string
	}
	var brokenConnections []*WebSocket
	var listenersCount int
	
	// 第一阶段：快速收集需要通知的targets（短时间持锁）
	listenersMutex.Lock()
	for ws, subs := range listeners {
		for id, listener := range subs {
			listenersCount++
			if listener.filters.Match(event) {
				targets = append(targets, struct {
					ws *WebSocket
					id string
				}{ws, id})
			}
		}
	}
	listenersMutex.Unlock()
	
	// 第二阶段：在锁外发送通知（避免长时间持锁）
	notifyCount := 0
	errorCount := 0
	
	for _, target := range targets {
		// 创建EventEnvelope时增加活跃计数
		atomic.AddInt64(&activeEventEnvelopes, 1)
		
		err := target.ws.WriteJSON(nostr.EventEnvelope{SubscriptionID: &target.id, Event: *event})
		if err != nil {
			errorCount++
			brokenConnections = append(brokenConnections, target.ws)
			fmt.Printf("notifyListeners error for listener %s: %v\n", target.id, err)
			// EventEnvelope发送失败，减少活跃计数
			atomic.AddInt64(&activeEventEnvelopes, -1)
		} else {
			notifyCount++
		}
	}
	atomic.StoreInt64(&allListeners, int64(listenersCount))
	
	// 第三阶段：清理死连接（再次短时间持锁）
	if len(brokenConnections) > 0 {
		atomic.AddInt64(&deadConnections, int64(len(brokenConnections)))
		
		var removedTotal int64
		listenersMutex.Lock()
		for _, deadWS := range brokenConnections {
			if subs, ok := listeners[deadWS]; ok {
				removedCount := len(subs)
				removedTotal += int64(removedCount)
				delete(listeners, deadWS)
				atomic.AddInt64(&activeListeners, -int64(removedCount))
				fmt.Printf("removed %d listeners for dead connection\n", removedCount)
			}
		}
		listenersMutex.Unlock()

		// METRICS
		if removedTotal > 0 {
			atomic.AddInt64(&metricRemovedWriteFail, removedTotal)
		}
	}
}
