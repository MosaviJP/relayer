package relayer

import "context"

const AUTH_CONTEXT_KEY = iota

func GetAuthStatus(ctx context.Context) (pubkey string, ok bool) {
	value := ctx.Value(AUTH_CONTEXT_KEY)
	if value == nil {
		return "", false
	}
	if ws, ok := value.(*WebSocket); ok {
		return ws.authed, true
	}
	return "", false
}

// GetUserAgent returns the User-Agent string stored in the context.
func GetUserAgent(ctx context.Context) string {
	if ctx != nil {
		if v := ctx.Value("userAgent"); v != nil {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// GetConnPubkey returns a pubkey associated with this connection, preferring
// authenticated pubkey (NIP-42). If not authenticated, it falls back to the
// optional "pubkey" provided via request header and stored in context.
func GetConnPubkey(ctx context.Context, ws *WebSocket) string {
	if ws != nil && ws.authed != "" {
		return ws.authed
	}
	if ctx != nil {
		if v := ctx.Value("userPubkey"); v != nil {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
