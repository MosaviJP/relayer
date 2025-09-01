package relayer

import (
	"context"
	"fmt"
	"regexp"

	"github.com/MosaviJP/eventstore"
	"github.com/nbd-wtf/go-nostr"
)

var nip20prefixmatcher = regexp.MustCompile(`^\w+: `)

// AddEvent has a business rule to add an event to the relayer
func AddEvent(ctx context.Context, relay Relay, evt *nostr.Event) (accepted bool, message string) {
	if evt == nil {
		return false, ""
	}

	store := relay.Storage(ctx)
	wrapper := &eventstore.RelayWrapper{
		Store: store,
	}
	advancedSaver, _ := store.(AdvancedSaver)

	if ok, msg := relay.AcceptEvent(ctx, evt); !ok {
		if msg == "" {
			msg = "blocked: event blocked by relay"
		}
		return false, msg
	}

	if 20000 <= evt.Kind && evt.Kind < 30000 {
		// do not store ephemeral events
	} else {
		if advancedSaver != nil {
			advancedSaver.BeforeSave(ctx, evt)
		}

		if saveErr := wrapper.Publish(ctx, *evt); saveErr != nil {
			switch saveErr {
			case eventstore.ErrDupEvent:
				return true, saveErr.Error()
			default:
				errmsg := saveErr.Error()
				if nip20prefixmatcher.MatchString(errmsg) {
					return false, errmsg
				} else {
					return false, fmt.Sprintf("error: failed to save (%s)", errmsg)
				}
			}
		}

		if advancedSaver != nil {
			advancedSaver.AfterSave(evt)
		}
	}

    notifyListeners(evt)

    // propagate to external listeners if supported (e.g., Redis Pub/Sub)
    if b, ok := relay.(EventBroadcaster); ok && evt != nil {
        b.BroadcastEvent(evt)
    }

	return true, ""
}

// AddEvents is a helper function to add multiple events to the relayer
// It filters out ephemeral events and calls PublishServal on the RelayWrapper
func AddEvents(ctx context.Context, relay Relay, events []nostr.Event) (accepted bool, message string) {
	if len(events) == 0 {
		return true, "AddEvents: no events to add"
	}

	store := relay.Storage(ctx)
	wrapper := &eventstore.RelayWrapper{
		Store: store,
	}

	var othersEvents []*nostr.Event
	for _, evt := range events {
		if nostr.IsEphemeralKind(evt.Kind) {
			continue
		}
		othersEvents = append(othersEvents, &evt)
	}

	if len(othersEvents) == 0 {
		return true, "AddEvents: no regular events to add"
	}

	if err := wrapper.PublishServal(ctx, othersEvents); err != nil {
		return false, fmt.Sprintf("AddEvents: errors: failed to save events (%s)", err.Error())
	}

    for _, evt := range events {
        notifyListeners(&evt)
        if b, ok := relay.(EventBroadcaster); ok {
            // broadcast each event individually
            e := evt
            b.BroadcastEvent(&e)
        }
    }

	return true, ""
}
