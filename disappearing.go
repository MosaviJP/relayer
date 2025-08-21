package relayer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/MosaviJP/eventstore/postgresql"
	"github.com/nbd-wtf/go-nostr"
)

// Helper functions
func isDisappearingMessage(evt nostr.Event) bool {
	for _, tag := range evt.Tags {
		if len(tag) >= 2 && tag[0] == "l" && tag[1] == "disappearing" {
			return true
		}
	}
	return false
}

func (s *Server) handleDisappearingMessage(ctx context.Context, evt nostr.Event) error {
	s.Log.Infof("Processing disappearing message event ID: %s from %s", evt.ID, evt.PubKey)
	
	var ttl int64
	var expiration time.Time
	
	// 提取TTL和expiration信息
	for _, tag := range evt.Tags {
		if len(tag) < 2 {
			continue
		}
		
		switch tag[0] {
		case "ttl":
			var err error
			ttl, err = strconv.ParseInt(tag[1], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid ttl value: %v", err)
			}
			if ttl <= 0 {
				return fmt.Errorf("TTL must be positive, got %d", ttl)
			}
		case "expiration":
			timestamp, err := strconv.ParseInt(tag[1], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid expiration timestamp: %v", err)
			}
			expiration = time.Unix(timestamp, 0)
			if expiration.Before(time.Now()) {
				return fmt.Errorf("message already expired")
			}
		}
	}

	// 验证必要的标签
	if ttl == 0 {
		return fmt.Errorf("missing ttl tag")
	}
	if expiration.IsZero() {
		return fmt.Errorf("missing expiration tag")
	}

	// 验证expiration时间必须大于created_at+ttl
	createdAt := time.Unix(int64(evt.CreatedAt), 0)
	minExpiration := createdAt.Add(time.Duration(ttl) * time.Second)
	if expiration.Before(minExpiration) {
		return fmt.Errorf("expiration time must be greater than created_at + ttl")
	}

	// 使用传入的 context (可能包含事务) 直接调用 PostgresBackend
	store := s.relay.Storage(ctx)
	if postgresBackend, ok := store.(*postgresql.PostgresBackend); ok {
		return postgresBackend.UpsertDisappearing(ctx, evt.ID, ttl, expiration, createdAt)
	}
	
	// 对于非 PostgreSQL 后端，记录警告但不报错
	s.Log.Warningf("Disappearing message not supported for this backend type")
	return nil
}

// handle disappearing message list - simplified to use PostgresBackend directly
func (s *Server) handleDisappearingMessageList(ctx context.Context, events []nostr.Event) error {
	if len(events) == 0 {
		return nil
	}
	
	s.Log.Infof("Processing disappearing message list with %d events", len(events))
	
	// 使用传入的 context (可能包含事务) 直接调用 PostgresBackend
	store := s.relay.Storage(ctx)
	postgresBackend, ok := store.(*postgresql.PostgresBackend)
	if !ok {
		s.Log.Warningf("Disappearing message not supported for this backend type")
		return nil
	}
	
	// 处理每个消失消息事件
	for _, evt := range events {
		var ttl int64
		var expiration time.Time
		
		// 提取TTL和expiration信息
		for _, tag := range evt.Tags {
			if len(tag) < 2 {
				continue
			}
			switch tag[0] {
			case "ttl":
				if parsed, err := strconv.ParseInt(tag[1], 10, 64); err == nil && parsed > 0 {
					ttl = parsed
				}
			case "expiration":
				if timestamp, err := strconv.ParseInt(tag[1], 10, 64); err == nil {
					expiration = time.Unix(timestamp, 0)
				}
			}
		}
		
		// 验证必要的标签
		if ttl == 0 || expiration.IsZero() {
			s.Log.Infof("Skipping event %s: missing ttl or expiration tags", evt.ID)
			continue
		}
		
		// 验证过期时间
		createdAt := time.Unix(int64(evt.CreatedAt), 0)
		minExpiration := createdAt.Add(time.Duration(ttl) * time.Second)
		if expiration.Before(minExpiration) || expiration.Before(time.Now()) {
			s.Log.Infof("Skipping event %s: invalid expiration time", evt.ID)
			continue
		}
		
		// 调用 PostgresBackend 的 UpsertDisappearing 方法 (支持事务上下文)
		if err := postgresBackend.UpsertDisappearing(ctx, evt.ID, ttl, expiration, createdAt); err != nil {
			s.Log.Errorf("Failed to store disappearing message %s: %v", evt.ID, err)
			return err
		}
		
		s.Log.Infof("Successfully saved disappearing message %s (TTL: %d, Expires: %s)",
			evt.ID, ttl, expiration.Format(time.RFC3339))
	}
	
	return nil
}
