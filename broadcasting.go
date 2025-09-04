package relayer

import (
	"context"
	"sync"

	"github.com/MosaviJP/eventstore"
	"github.com/jmoiron/sqlx"
	"github.com/nbd-wtf/go-nostr"
)

func BroadcastEvent(evt *nostr.Event) {
	notifyListeners(evt)
}

// post-commit broadcast queue keyed by transaction pointer
var (
	postCommitMu     sync.Mutex
	postCommitQueues = make(map[*sqlx.Tx][]*nostr.Event)
)

// queuePostCommitBroadcast enqueues an event for broadcasting after the current transaction commits.
// Returns true if the event was queued (i.e., a transaction exists in context), false otherwise.
func queuePostCommitBroadcast(ctx context.Context, evt *nostr.Event) bool {
	if evt == nil {
		return false
	}
	if tx, ok := eventstore.TxFrom(ctx); ok && tx != nil {
		postCommitMu.Lock()
		postCommitQueues[tx] = append(postCommitQueues[tx], evt)
		postCommitMu.Unlock()
		return true
	}
	return false
}

// flushPostCommitBroadcast flushes queued events for a committed transaction
func flushPostCommitBroadcast(tx *sqlx.Tx, relay Relay) {
	if tx == nil { return }
	postCommitMu.Lock()
	events := postCommitQueues[tx]
	delete(postCommitQueues, tx)
	postCommitMu.Unlock()
	for _, evt := range events {
		notifyListeners(evt)
		if b, ok := relay.(EventBroadcaster); ok && evt != nil {
			b.BroadcastEvent(evt)
		}
	}
}

// discardPostCommitBroadcast drops any queued events for a transaction without broadcasting
func discardPostCommitBroadcast(tx *sqlx.Tx) {
	if tx == nil { return }
	postCommitMu.Lock()
	delete(postCommitQueues, tx)
	postCommitMu.Unlock()
}
