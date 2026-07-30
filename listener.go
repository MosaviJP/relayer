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

	// 关闭闸门，标记正在/已关闭的 ws，防止并发 REQ 回填订阅
	closingWS      = make(map[*WebSocket]struct{})
)

type removalReason int
const (
    reasonDisconnect removalReason = iota
    reasonWriteFail
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
	
	// print ws to check it exists and connected, make sure don't cause panic in printf
	if diagLogVerbose {
		if ws != nil {
			if ws.conn != nil {
				fmt.Printf("NOSTR_LISTENER_SET ws=%p conn=%p id=%s\n", ws, ws.conn, id)
			} else {
				fmt.Printf("NOSTR_LISTENER_SET ws=%p conn=nil id=%s\n", ws, id)
			}
		} else {
			fmt.Printf("NOSTR_LISTENER_SET ws=nil id=%s\n", id)
		}
	}
	// 如果 ws 已经在关闭状态，直接丢弃本次REQ，避免并发问题
	if _, closing := closingWS[ws]; closing {
		listenersMutex.Unlock()
		atomic.AddInt64(&metricReqDroppedOnClosed, 1)
		if diagLogVerbose {
			fmt.Printf("NOSTR_LISTENER_DROP ws=%p conn=%p id=%s reason=closing\n", ws, ws.conn, id)
		}
		return
	}

	subs, ok := listeners[ws]
	if !ok {
		subs = make(map[string]*Listener)
		listeners[ws] = subs
	}

	_, idExisted := subs[id]
	if diagLogVerbose {
		fmt.Printf("NOSTR_LISTENER_SET ws=%p conn=%p id=%s existed_ws=%t existed_id=%t\n",
			ws, ws.conn, id, ok, idExisted)
	}
	subs[id] = &Listener{filters: filters}
	listenersMutex.Unlock()

	if !idExisted {
		atomic.AddInt64(&metricReqNew, 1)
		atomic.AddInt64(&activeListeners, 1)
	} else {
		atomic.AddInt64(&metricReqUpdate, 1)
	}
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
func removeListener(ws *WebSocket, reason removalReason) int {
	var removedCount int

	listenersMutex.Lock()

	// 计算移除的listener数量
	if subs, ok := listeners[ws]; ok {
		removedCount = len(subs)
		clear(subs)
		delete(listeners, ws)
	}
	delete(closingWS, ws)
	listenersMutex.Unlock()
	
	if removedCount > 0 {
		// METRICS（按原因归因，只加一次）
        switch reason {
        case reasonDisconnect:
            atomic.AddInt64(&metricRemovedDisconnect, int64(removedCount))
        case reasonWriteFail:
            atomic.AddInt64(&metricRemovedWriteFail, int64(removedCount))
        }
		atomic.AddInt64(&activeListeners, -int64(removedCount))
	}

	if diagLogVerbose {
		fmt.Printf("NOSTR_REMOVE_LISTENER ws=%p conn=%p removed_subs=%d\n", ws, ws.conn, removedCount)
	}
	return removedCount
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
			} else {
				notifyCount++
			}
		atomic.AddInt64(&activeEventEnvelopes, -1)
	}
	atomic.StoreInt64(&allListeners, int64(listenersCount))
	
	// 第三阶段：清理死连接（再次短时间持锁）
	if len(brokenConnections) > 0 {
		atomic.AddInt64(&deadConnections, int64(len(brokenConnections)))
		
		for _, deadWS := range brokenConnections {
			listenersMutex.Lock()
			closingWS[deadWS] = struct{}{}
			listenersMutex.Unlock()
			removedCount := removeListener(deadWS, reasonWriteFail)
			if removedCount > 0 {
				fmt.Printf("removed %d listeners for dead connection ws=%p\n", removedCount, deadWS)
			}
		}
	}
}
