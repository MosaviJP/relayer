package relayer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"sync"

	"github.com/MosaviJP/eventstore"
	"github.com/MosaviJP/eventstore/postgresql"
	"github.com/jmoiron/sqlx"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// GroupManagementConfig holds the configuration for group management
type GroupManagementConfig struct {
	BotPrivateKey string
}

// GroupConfigProvider interface for getting group management configuration
type GroupConfigProvider interface {
	GetGroupManagementConfig() interface{} // Use interface{} for flexibility
}

// GroupMembershipData represents the data structure for group membership based on entgo schema
type GroupMembershipData struct {
	EventID             string  `json:"event_id" db:"event_id"`
	GroupID             string  `json:"group_id" db:"group_id"`
	MemberPubkey        string  `json:"member_pubkey" db:"member_pubkey"`
	EncryptedSessionKey string  `json:"encrypted_session_key" db:"encrypted_session_key"`
	AdminPubkey         string  `json:"admin_pubkey" db:"admin_pubkey"`
	GenPubkey           string  `json:"gen_pubkey" db:"gen_pubkey"`
	PreGenPubkey        *string `json:"pre_gen_pubkey" db:"pre_gen_pubkey"`
	Latest              bool    `json:"latest" db:"latest"`
	DecryptType         int     `json:"decrypt_type" db:"decrypt_type"`
	CreatedAt           int64   `json:"created_at" db:"created_at"`
	InsertedAt          int64   `json:"inserted_at" db:"inserted_at"`
}

// AdminKeyData represents the data structure for admin keys based on entgo schema
type AdminKeyData struct {
	EventID             string `json:"event_id" db:"event_id"`
	GroupID             string `json:"group_id" db:"group_id"`
	OwnerPubkey         string `json:"owner_pubkey" db:"owner_pubkey"`
	UserPubkey          string `json:"user_pubkey" db:"user_pubkey"`
	EncryptedPrivateKey string `json:"encrypted_private_key" db:"encrypted_private_key"`
	Latest              bool   `json:"latest" db:"latest"`
	CreatedAt           int64  `json:"created_at" db:"created_at"`
	InsertedAt          int64  `json:"inserted_at" db:"inserted_at"`
}

// SessionKeyRotationRequest represents the structure for 3046 events (gen-key update)
type SessionKeyRotationRequest struct {
	GroupID       string     `json:"groupId"`
	GenPubkey     string     `json:"genPubkey,omitempty"`
	PreGenPubkey  *string    `json:"preGenPubkey,omitempty"`
	EncryptPubkey string     `json:"encryptPubkey,omitempty"`
	Members       [][]string `json:"members,omitempty"`
	CreatedAt     int64      `json:"createdAt,omitempty"`
}

// AdminKeyUpdateRequest represents the structure for 3046 events (admin-key update)
type AdminKeyUpdateRequest struct {
	GroupID       string     `json:"groupId"`
	EncryptPubkey string     `json:"encryptPubkey,omitempty"`
	Roles         [][]string `json:"roles,omitempty"`
	CreatedAt     int64      `json:"createdAt,omitempty"`
}

// MemberAdditionRequest represents the structure for 3047 events (same as session key rotation)
type MemberAdditionRequest struct {
	Type          string     `json:"type,omitempty"`
	GroupID       string     `json:"groupId"`
	GenPubkey     string     `json:"genPubkey"`
	PreGenPubkey  string     `json:"preGenPubkey"`
	EncryptPubkey string     `json:"encryptPubkey,omitempty"`
	Members       [][]string `json:"members,omitempty"`
	CreatedAt     int64      `json:"createdAt"`
}

// IsShareableRequest represents the structure for 20041 events
type IsShareableRequest struct {
	GroupID     string `json:"groupId"`
	IsShareable bool   `json:"shareable"`
}

// JoinApprovalRequest represents the structure for 20042 events
type JoinApprovalRequest struct {
	GroupID                string `json:"groupId"`
	IsJoinApprovalRequired bool   `json:"review"`
}

// AliasRequest represents the structure for 39304 events
type AliasRequest struct {
	GroupID string `json:"groupId"`
	Alias   string `json:"alias"`
}

// GroupApprovalData represents the data structure for group approval status
type GroupApprovalData struct {
	GroupID                string    `json:"group_id" db:"group_id"`
	IsJoinApprovalRequired bool      `json:"is_join_approval_required" db:"is_join_approval_required"`
	CreatedAt              time.Time `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time `json:"updated_at" db:"updated_at"`
	IsDissolved            bool      `json:"is_dissolved" db:"is_dissolved"`
}

// MemberAliasData represents the data structure for member aliases
type MemberAliasData struct {
	GroupID      string    `json:"group_id" db:"group_id"`
	MemberPubkey string    `json:"member_pubkey" db:"member_pubkey"`
	Alias        string    `json:"alias" db:"alias"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// Sentinel errors to signal non-fatal skips for group management handling
var (
	errBotKeyNotConfigured         = fmt.Errorf("bot private key not configured")
	errUnsupportedGroupMgmtBackend = fmt.Errorf("group management requires PostgreSQL backend")
)

// optional schema provider interface; if implemented by relay, used to fetch schema
type GroupSchemaProvider interface {
	GetGroupManagementSchema() string
}

var schemaNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// getGroupSchema resolves schema for group management tables.
// Priority: relay provider -> env GROUP_MGMT_SCHEMA -> env RELAY_GROUP_SCHEMA -> "moss_api"
func (s *Server) getGroupSchema() string {
	if p, ok := s.relay.(GroupSchemaProvider); ok {
		if name := p.GetGroupManagementSchema(); schemaNameRe.MatchString(name) {
			return name
		} else if name != "" {
			s.Log.Warningf("invalid schema from provider: %q; fallback to default", name)
		}
	}
	if env := os.Getenv("GROUP_MGMT_SCHEMA"); env != "" {
		if schemaNameRe.MatchString(env) {
			return env
		}
		s.Log.Warningf("invalid GROUP_MGMT_SCHEMA=%q; fallback to default", env)
	}
	if env := os.Getenv("RELAY_GROUP_SCHEMA"); env != "" {
		if schemaNameRe.MatchString(env) {
			return env
		}
		s.Log.Warningf("invalid RELAY_GROUP_SCHEMA=%q; fallback to default", env)
	}
	return "moss_api"
}

// ---- Permission helpers ----

// groupHasAnyAdmin returns true if the group has any admin key records
func (s *Server) groupHasAnyAdmin(ctx context.Context, backend *postgresql.PostgresBackend, groupID string) (bool, error) {
	schema := s.getGroupSchema()
	query := fmt.Sprintf(`SELECT 1 FROM %s.admin_keys WHERE group_id = $1 LIMIT 1`, schema)
	if tx, ok := eventstore.TxFrom(ctx); ok {
		var x int
		err := tx.QueryRowContext(ctx, query, groupID).Scan(&x)
		if err == sql.ErrNoRows {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
	var x int
	err := backend.DB.QueryRowContext(ctx, query, groupID).Scan(&x)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// isOwner returns true if pubkey is an owner for the group
func (s *Server) isOwner(ctx context.Context, backend *postgresql.PostgresBackend, groupID, pubkey string) (bool, error) {
	schema := s.getGroupSchema()
	query := fmt.Sprintf(`SELECT 1 FROM %s.admin_keys WHERE group_id = $1 AND owner_pubkey = $2 LIMIT 1`, schema)
	if tx, ok := eventstore.TxFrom(ctx); ok {
		var x int
		err := tx.QueryRowContext(ctx, query, groupID, pubkey).Scan(&x)
		if err == sql.ErrNoRows {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
	var x int
	err := backend.DB.QueryRowContext(ctx, query, groupID, pubkey).Scan(&x)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// isAdmin returns true if pubkey is an admin (has admin key with latest=true)
func (s *Server) isAdmin(ctx context.Context, backend *postgresql.PostgresBackend, groupID, pubkey string) (bool, error) {
	schema := s.getGroupSchema()
	query := fmt.Sprintf(`SELECT 1 FROM %s.admin_keys WHERE group_id = $1 AND user_pubkey = $2 AND latest = true LIMIT 1`, schema)
	if tx, ok := eventstore.TxFrom(ctx); ok {
		var x int
		err := tx.QueryRowContext(ctx, query, groupID, pubkey).Scan(&x)
		if err == sql.ErrNoRows {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
	var x int
	err := backend.DB.QueryRowContext(ctx, query, groupID, pubkey).Scan(&x)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// isMember returns true if pubkey is a current member of the group
func (s *Server) isMember(ctx context.Context, backend *postgresql.PostgresBackend, groupID, pubkey string) (bool, error) {
	schema := s.getGroupSchema()
	query := fmt.Sprintf(`SELECT 1 FROM %s.group_memberships WHERE group_id = $1 AND member_pubkey = $2 AND latest = true LIMIT 1`, schema)
	if tx, ok := eventstore.TxFrom(ctx); ok {
		var x int
		err := tx.QueryRowContext(ctx, query, groupID, pubkey).Scan(&x)
		if err == sql.ErrNoRows {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
	var x int
	err := backend.DB.QueryRowContext(ctx, query, groupID, pubkey).Scan(&x)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// preprocess group_current_members table
// if there is no record for the group in the table, insert the records from group_memberships
// if there are records, check if they are up to date (based on created_at between group_memberships and group_current_members)
func (s *Server) preprocessCurrentMembersInline(ctx context.Context, backend *postgresql.PostgresBackend, groupID string) error {
	schema := s.getGroupSchema()
	queryCheck := fmt.Sprintf(`SELECT 1 FROM %s.group_current_members WHERE group_id = $1 LIMIT 1`, schema)
	var x int
	if tx, ok := eventstore.TxFrom(ctx); ok {
		err := tx.QueryRowContext(ctx, queryCheck, groupID).Scan(&x)
		if err == nil {
			// Record exists, check if up to date
			return nil
		}
		if err != sql.ErrNoRows {
			return err
		}
		// No record, insert from group_memberships
		_, err = tx.ExecContext(ctx, fmt.Sprintf(`
INSERT INTO %s.group_current_members (group_id, member_pubkey, created_at, updated_at)
SELECT group_id, member_pubkey, created_at, inserted_at
FROM %s.group_memberships
WHERE group_id = $1 AND latest = true
`, schema, schema), groupID)
		return err
	}
	err := backend.DB.QueryRowContext(ctx, queryCheck, groupID).Scan(&x)
	if err == nil {
		// Record exists, nothing to do
		return nil
	}
	// No record, insert from group_memberships
	_, err = backend.DB.ExecContext(ctx, fmt.Sprintf(`
INSERT INTO %s.group_current_members (group_id, member_pubkey, created_at, updated_at)
SELECT group_id, member_pubkey, created_at, inserted_at
FROM %s.group_memberships
WHERE group_id = $1 AND latest = true
`, schema, schema), groupID)
	return err
}

// isJoinApprovalRequired returns whether the group currently requires join approval.
// If no record exists, defaults to false (no approval required).
func (s *Server) isJoinApprovalRequired(ctx context.Context, backend *postgresql.PostgresBackend, groupID string) (bool, error) {
	schema := s.getGroupSchema()
	query := fmt.Sprintf(`SELECT is_join_approval_required FROM %s.group_approval_status WHERE group_id = $1 LIMIT 1`, schema)
	var required bool
	if tx, ok := eventstore.TxFrom(ctx); ok {
		err := tx.QueryRowContext(ctx, query, groupID).Scan(&required)
		if err == sql.ErrNoRows {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return required, nil
	}
	err := backend.DB.QueryRowContext(ctx, query, groupID).Scan(&required)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return required, nil
}

// currentDisbandStatus returns whether the group is currently marked as dissolved.
func (s *Server) currentDisbandStatus(ctx context.Context, backend *postgresql.PostgresBackend, groupID string) (bool, error) {
	schema := s.getGroupSchema()
	query := fmt.Sprintf(`SELECT is_dissolved FROM %s.group_approval_status WHERE group_id = $1 LIMIT 1`, schema)
	var dissolved bool
	if tx, ok := eventstore.TxFrom(ctx); ok {
		err := tx.QueryRowContext(ctx, query, groupID).Scan(&dissolved)
		if err == sql.ErrNoRows {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return dissolved, nil
	}
	err := backend.DB.QueryRowContext(ctx, query, groupID).Scan(&dissolved)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return dissolved, nil
}

// ---- Consolidated permission helpers ----

// requireAdminOrFresh requires the sender to be admin if the group already has any admin
func (s *Server) requireAdminOrFresh(ctx context.Context, backend *postgresql.PostgresBackend, groupID, pubkey string) error {
	hasAdmin, err := s.groupHasAnyAdmin(ctx, backend, groupID)
	if err != nil {
		s.Log.Warningf("permission check (hasAdmin) failed for group %s: %v; allowing as fresh", groupID, err)
		return nil
	}
	if hasAdmin {
		ok, err := s.isAdmin(ctx, backend, groupID, pubkey)
		if err != nil {
			return fmt.Errorf("permission check failed: %w", err)
		}
		if !ok {
			return fmt.Errorf("forbidden: requires admin of group %s", groupID)
		}
	}
	return nil
}

// requireOwnerOrFresh requires the sender to be owner if the group already has any admin
func (s *Server) requireOwnerOrFresh(ctx context.Context, backend *postgresql.PostgresBackend, groupID, pubkey string) error {
	hasAdmin, err := s.groupHasAnyAdmin(ctx, backend, groupID)
	if err != nil {
		s.Log.Warningf("permission check (hasAdmin) failed for group %s: %v; allowing as fresh", groupID, err)
		return nil
	}
	if hasAdmin {
		ok, err := s.isOwner(ctx, backend, groupID, pubkey)
		if err != nil {
			return fmt.Errorf("permission check failed: %w", err)
		}
		if !ok {
			return fmt.Errorf("forbidden: requires owner of group %s", groupID)
		}
	}
	return nil
}

// requireSenderMember ensures the sender is a current member of the group
func (s *Server) requireSenderMember(ctx context.Context, backend *postgresql.PostgresBackend, groupID, pubkey string) error {
	ok, err := s.isMember(ctx, backend, groupID, pubkey)
	if err != nil {
		return fmt.Errorf("failed to verify sender membership: %w", err)
	}
	if !ok {
		return fmt.Errorf("forbidden: sender %s is not a member of group %s", pubkey, groupID)
	}
	return nil
}

// checkJoinApprovalAllowsAdd returns error if join approval is required (forbids 3047)
func (s *Server) checkJoinApprovalAllowsAdd(ctx context.Context, backend *postgresql.PostgresBackend, groupID string) error {
	required, err := s.isJoinApprovalRequired(ctx, backend, groupID)
	if err != nil {
		s.Log.Warningf("join approval check failed for group %s: %v; treating as not required", groupID, err)
		return nil
	}
	if required {
		return fmt.Errorf("forbidden: group %s requires join approval; cannot add members via 3047", groupID)
	}
	return nil
}

// handleGroupManagementEventInline processes group management events inline
func (s *Server) handleGroupManagementEventInline(ctx context.Context, evt *nostr.Event) error {
	// Get bot private key from relay config
	var botPrivateKey string
	if configProvider, ok := s.relay.(interface{ GetGroupManagementConfig() string }); ok {
		botPrivateKey = configProvider.GetGroupManagementConfig()
	}

	if botPrivateKey == "" {
		return errBotKeyNotConfigured
	}

	// Get the PostgreSQL backend first
	store := s.relay.Storage(ctx)
	postgresBackend, ok := store.(*postgresql.PostgresBackend)
	if !ok {
		return errUnsupportedGroupMgmtBackend
	}

	// Ensure schema exists once before processing - use direct DB connection
	if err := s.ensureGroupMembershipsSchemaInline(ctx, postgresBackend); err != nil {
		return fmt.Errorf("failed to ensure group management schema: %w", err)
	}

	// Check if we already have a transaction in context
	var localTx *sqlx.Tx
	var err error
	if _, hasTx := eventstore.TxFrom(ctx); !hasTx {
		// No transaction in context, create one for group management operations
		localTx, err = postgresBackend.DB.BeginTxx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}

		// Add transaction to context
		ctx = eventstore.WithTx(ctx, localTx)

		// Ensure transaction is committed or rolled back
		defer func() {
			if err != nil {
				localTx.Rollback()
				discardPostCommitBroadcast(localTx)
			} else {
				if cErr := localTx.Commit(); cErr != nil {
					discardPostCommitBroadcast(localTx)
				} else {
					flushPostCommitBroadcast(localTx, s.relay)
				}
			}
		}()
	}

	switch evt.Kind {
	case 3046:
		err = s.handleSessionKeyRotationEvent(ctx, evt, botPrivateKey)
	case 3047:
		err = s.handleMemberAdditionEvent(ctx, evt, botPrivateKey)
	case 20041:
		err = s.handleIsShareableEvent(ctx, evt, botPrivateKey)
	case 20042:
		err = s.handleJoinApprovalEvent(ctx, evt, botPrivateKey)
	case 39304:
		err = s.handleAliasEvent(ctx, evt, botPrivateKey)
	default:
		err = fmt.Errorf("unsupported group management event kind: %d", evt.Kind)
	}

	return err
}

// handleSessionKeyRotationEvent processes 3046 events (gen-key or admin-key updates)
func (s *Server) handleSessionKeyRotationEvent(ctx context.Context, evt *nostr.Event, botPrivateKey string) error {
	s.Log.Infof("Processing 3046 event ID: %s from %s", evt.ID, evt.PubKey)

	// Decrypt the content using NIP-04
	decryptedContent, err := s.decryptMessage(evt.Content, botPrivateKey, evt.PubKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt 3046 content: %w", err)
	}

	s.Log.Infof("Decrypted 3046 content: %s", decryptedContent)

	// Try to determine if this is gen-key update (members>0) or admin-key update (roles>0)
	var rawData map[string]interface{}
	if err := json.Unmarshal([]byte(decryptedContent), &rawData); err != nil {
		return fmt.Errorf("failed to parse 3046 raw data: %w", err)
	}

	store := s.relay.Storage(ctx)
	postgresBackend, ok := store.(*postgresql.PostgresBackend)
	if !ok {
		return fmt.Errorf("group management requires PostgreSQL backend")
	}

	hasMembers := false
	hasRoles := false
	isDisband := false
	if eventType, ok := rawData["type"].(string); ok {
		if strings.ToLower(eventType) == "members" {
			hasMembers = true
		} else if strings.ToLower(eventType) == "admins" {
			hasRoles = true
		} else if strings.ToLower(eventType) == "disband" {
			isDisband = true
		}
	} else {
		// Default case
		if v, ok := rawData["members"]; ok && v != nil {
			if arr, ok2 := v.([]interface{}); ok2 && len(arr) > 0 {
				hasMembers = true
			}
		}
		if v, ok := rawData["admins"]; ok && v != nil {
			if arr, ok2 := v.([]interface{}); ok2 && len(arr) > 0 {
				hasRoles = true
			}
		}

		if hasMembers && hasRoles {
			return fmt.Errorf("invalid 3046 event: both members and admins present")
		}
	}
	switch {
	case hasMembers:
		return s.handleGenKeyUpdate(ctx, evt, decryptedContent, botPrivateKey, postgresBackend)
	case hasRoles:
		return s.handleAdminKeyUpdate(ctx, evt, decryptedContent, botPrivateKey, postgresBackend)
	case isDisband:
		return s.handleGroupDisbandEvent(ctx, evt, decryptedContent, botPrivateKey, postgresBackend)
	default:
		return fmt.Errorf("invalid 3046 event: neither members nor admins provided")
	}
}

// handleGenKeyUpdate processes gen-key updates (3046 with members)
func (s *Server) handleGenKeyUpdate(ctx context.Context, evt *nostr.Event, decryptedContent, botPrivateKey string, backend *postgresql.PostgresBackend) error {
	var request SessionKeyRotationRequest
	if err := json.Unmarshal([]byte(decryptedContent), &request); err != nil {
		return fmt.Errorf("failed to parse gen-key update request: %w", err)
	}

	s.Log.Infof("Gen-key update for group %s, %d members updated",
		request.GroupID, len(request.Members))

	// Permission: require admin; if fresh group (no admin yet) allow
	if err := s.requireAdminOrFresh(ctx, backend, request.GroupID, evt.PubKey); err != nil {
		return err
	}

	// Determine the admin pubkey (encryptPubkey or sender)
	encryptKey := request.EncryptPubkey
	if encryptKey == "" {
		encryptKey = evt.PubKey
	}

	// Get transaction from context (should always exist now)
	tx, hasTx := eventstore.TxFrom(ctx)
	if !hasTx {
		return fmt.Errorf("transaction missing from context")
	}

	// Query existing records for this event to avoid duplicate processing
	schema := s.getGroupSchema()
	existingQuery := fmt.Sprintf(`SELECT member_pubkey FROM %s.group_memberships WHERE event_id = $1 AND group_id = $2`, schema)
	var existingMembers []string
	rows, err := tx.QueryContext(ctx, existingQuery, evt.ID, request.GroupID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var memberPubkey string
			if err := rows.Scan(&memberPubkey); err == nil {
				existingMembers = append(existingMembers, memberPubkey)
			}
		}
	}

	existingMemberMap := make(map[string]bool)
	for _, member := range existingMembers {
		existingMemberMap[member] = true
	}

	// Process session keys for all members
	for _, member := range request.Members {
		if len(member) < 2 {
			s.Log.Warningf("Invalid member data: %v", member)
			continue
		}

		memberPubKey := member[0]
		encryptedGenPrivkey := member[1] // This is nip44V2Encrypt(role privkey, member pubkey, gen-privkey)

		// Skip if this member already exists for this event
		if existingMemberMap[memberPubKey] {
			s.Log.Infof("Session key for member %s already exists for event %s, skipping", memberPubKey, evt.ID)
			continue
		}

		membershipData := GroupMembershipData{
			EventID:             evt.ID,
			GroupID:             request.GroupID,
			MemberPubkey:        memberPubKey,
			EncryptedSessionKey: encryptedGenPrivkey,
			AdminPubkey:         encryptKey,
			GenPubkey:           request.GenPubkey,
			PreGenPubkey:        request.PreGenPubkey,
			Latest:              false, // Will be set correctly after all inserts
			DecryptType:         0,     // Admin-generated
			CreatedAt:           request.CreatedAt,
			InsertedAt:          time.Now().Unix(),
		}

		err := s.upsertGroupMembershipInline(ctx, backend, membershipData)
		if err != nil {
			s.Log.Errorf("Failed to update membership for user %s in group %s: %v",
				memberPubKey, request.GroupID, err)
			// Continue processing other users, but log this as a warning for debugging
			s.Log.Warningf("Continuing to process other members after error for %s", memberPubKey)
		} else {
			s.Log.Infof("Successfully upserted membership for user %s in group %s", memberPubKey, request.GroupID)
		}
	}

	// Always update latest flags to ensure consistency
	s.Log.Infof("Starting to update latest flags for group %s", request.GroupID)
	err = s.updateLatestFlagsForGroupMembership(ctx, backend, request.GroupID)
	if err != nil {
		s.Log.Errorf("Failed to update latest flags for group %s: %v", request.GroupID, err)
		return err
	}
	s.Log.Infof("Successfully updated latest flags for group %s", request.GroupID)

	// Update group_current_members table using this snapshot
	var snapshotCreatedAt time.Time
	if request.CreatedAt > 0 {
		snapshotCreatedAt = time.Unix(request.CreatedAt, 0).UTC()
	} else {
		snapshotCreatedAt = evt.CreatedAt.Time().UTC()
	}
	s.Log.Infof("Starting to update group_current_members for group %s (snapshot at %s)", request.GroupID, snapshotCreatedAt)

	if err := s.updateGroupCurrentMembersInline(ctx, backend, request.GroupID, "", &snapshotCreatedAt, request.Members); err != nil {
		s.Log.Errorf("Failed to update group_current_members for group %s: %v", request.GroupID, err)
		return err
	}

	// After rotating gen key, republish the alias list (39305) to the new gen_pubkey
	if err := s.publishAliasListForGroup(ctx, backend, request.GroupID, botPrivateKey); err != nil {
		// Do not fail the rotation if publishing fails; just log
		s.Log.Errorf("Failed to publish alias list (39305) for group %s after gen-key update: %v", request.GroupID, err)
	}

	return nil
}

// updateLatestFlagsForGroupMembership ensures only the records with max created_at have latest=true
func (s *Server) updateLatestFlagsForGroupMembership(ctx context.Context, backend *postgresql.PostgresBackend, groupID string) error {
	tx, hasTx := eventstore.TxFrom(ctx)
	if !hasTx {
		return fmt.Errorf("transaction required for latest flag updates")
	}

	schema := s.getGroupSchema()
	latestGenQuery := fmt.Sprintf(`
		SELECT gen_pubkey
		FROM %s.group_memberships
		WHERE group_id = $1
		  AND created_at = (
			SELECT max(created_at)
			FROM %s.group_memberships
			WHERE group_id = $1
		  )
		ORDER BY gen_pubkey DESC
		LIMIT 1
	`, schema, schema)

	var latestGen sql.NullString
	if err := tx.QueryRowContext(ctx, latestGenQuery, groupID).Scan(&latestGen); err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return fmt.Errorf("failed to determine latest gen_pubkey: %w", err)
	}
	if !latestGen.Valid || latestGen.String == "" {
		return nil
	}

	reset := fmt.Sprintf(`
		UPDATE %s.group_memberships
		SET latest = false
		WHERE group_id = $1 AND latest = true AND gen_pubkey <> $2
	`, schema)
	if _, err := tx.ExecContext(ctx, reset, groupID, latestGen.String); err != nil {
		return fmt.Errorf("failed to reset latest flags: %w", err)
	}

	set := fmt.Sprintf(`
		UPDATE %s.group_memberships
		SET latest = true
		WHERE group_id = $1 AND gen_pubkey = $2 AND latest = false
	`, schema)
	if _, err := tx.ExecContext(ctx, set, groupID, latestGen.String); err != nil {
		return fmt.Errorf("failed to set latest flags: %w", err)
	}

	s.Log.Infof("Updated latest flags for group %s", groupID)
	return nil
}

// handleAdminKeyUpdate processes admin-key updates (3046 with roles)
func (s *Server) handleAdminKeyUpdate(ctx context.Context, evt *nostr.Event, decryptedContent, botPrivateKey string, backend *postgresql.PostgresBackend) error {
	var request AdminKeyUpdateRequest
	if err := json.Unmarshal([]byte(decryptedContent), &request); err != nil {
		return fmt.Errorf("failed to parse admin-key update request: %w", err)
	}

	s.Log.Infof("Admin-key update for group %s, %d roles updated",
		request.GroupID, len(request.Roles))

	// Permission: require owner; if no admin_keys exist yet for this group, allow (fresh group creation)
	hasAdmin, errPerm := s.groupHasAnyAdmin(ctx, backend, request.GroupID)
	if errPerm != nil {
		return fmt.Errorf("permission check failed: %w", errPerm)
	}
	if hasAdmin {
		okOwner, errOwner := s.isOwner(ctx, backend, request.GroupID, evt.PubKey)
		if errOwner != nil {
			return fmt.Errorf("permission check failed: %w", errOwner)
		}
		if !okOwner {
			return fmt.Errorf("forbidden: 3046(admin-keys) requires owner of group %s", request.GroupID)
		}
	}

	// Process admin keys for all roles
	for _, role := range request.Roles {
		if len(role) < 2 {
			s.Log.Warningf("Invalid role data: %v", role)
			continue
		}

		rolePubkey := role[0]
		encryptedAdminPrivkey := role[1] // This is nip44V2Encrypt(owner privkey, role pubkey, admin-privkey)

		adminKeyData := AdminKeyData{
			EventID:             evt.ID,
			GroupID:             request.GroupID,
			OwnerPubkey:         evt.PubKey, // Event sender is the owner
			UserPubkey:          rolePubkey,
			EncryptedPrivateKey: encryptedAdminPrivkey,
			Latest:              false, // Will be set correctly after all inserts
			CreatedAt:           request.CreatedAt,
			InsertedAt:          time.Now().Unix(),
		}

		err := s.upsertAdminKeyInline(ctx, backend, adminKeyData)
		if err != nil {
			s.Log.Errorf("Failed to update admin key for user %s in group %s: %v",
				rolePubkey, request.GroupID, err)
			// Continue processing other roles
		}
	}

	// Always update latest flags to ensure consistency
	err := s.updateLatestFlagsForAdminKeys(ctx, backend, request.GroupID)
	if err != nil {
		s.Log.Errorf("Failed to update latest flags for admin keys in group %s: %v", request.GroupID, err)
		return err
	}

	return nil
}

// updateLatestFlagsForAdminKeys ensures only the records with max created_at have latest=true
func (s *Server) updateLatestFlagsForAdminKeys(ctx context.Context, backend *postgresql.PostgresBackend, groupID string) error {
	tx, hasTx := eventstore.TxFrom(ctx)
	if !hasTx {
		return fmt.Errorf("transaction required for admin key latest flag updates")
	}

	// Compatibility-safe SQL-only implementation to avoid type issues (BIGINT vs TIMESTAMPTZ)
	{
		schema := s.getGroupSchema()
		reset := fmt.Sprintf(`
            UPDATE %s.admin_keys 
            SET latest = false 
            WHERE group_id = $1 AND latest = true AND created_at <> (
                SELECT max(created_at) FROM %s.admin_keys WHERE group_id = $1
            )
        `, schema, schema)
		if _, err := tx.ExecContext(ctx, reset, groupID); err != nil {
			return fmt.Errorf("failed to reset admin key latest flags: %w", err)
		}

		set := fmt.Sprintf(`
            UPDATE %s.admin_keys 
            SET latest = true 
            WHERE group_id = $1 AND latest = false AND created_at = (
                SELECT max(created_at) FROM %s.admin_keys WHERE group_id = $1
            )
        `, schema, schema)
		if _, err := tx.ExecContext(ctx, set, groupID); err != nil {
			return fmt.Errorf("failed to set admin key latest flags: %w", err)
		}

		s.Log.Infof("Updated latest flags for admin keys in group %s", groupID)
		return nil
	}

	// Find the current maximum created_at
	schema := s.getGroupSchema()
	latestQuery := fmt.Sprintf(`
		SELECT MAX(created_at) 
		FROM %s.admin_keys 
		WHERE group_id = $1
	`, schema)
	var maxCreatedAt int64
	err := tx.QueryRowContext(ctx, latestQuery, groupID).Scan(&maxCreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			// No records for this group, nothing to update
			return nil
		}
		return fmt.Errorf("failed to query latest admin key record: %w", err)
	}

	// Reset only the records that are currently latest=true but should not be
	resetLatestQuery := fmt.Sprintf(`
		UPDATE %s.admin_keys 
		SET latest = false 
		WHERE group_id = $1 AND latest = true AND created_at != $2
	`, schema)
	_, err = tx.ExecContext(ctx, resetLatestQuery, groupID, maxCreatedAt)
	if err != nil {
		return fmt.Errorf("failed to reset admin key latest flags: %w", err)
	}

	// Set latest=true for records with the maximum created_at that aren't already latest
	setLatestQuery := fmt.Sprintf(`
		UPDATE %s.admin_keys 
		SET latest = true 
		WHERE group_id = $1 AND created_at = $2 AND latest = false
	`, schema)
	_, err = tx.ExecContext(ctx, setLatestQuery, groupID, maxCreatedAt)
	if err != nil {
		return fmt.Errorf("failed to set admin key latest flags: %w", err)
	}

	s.Log.Infof("Updated latest flags for admin keys in group %s (max created_at: %d)", groupID, maxCreatedAt)
	return nil
}

func (s *Server) handleGroupDisbandEvent(ctx context.Context, evt *nostr.Event, decryptedContent, botPrivateKey string, backend *postgresql.PostgresBackend) error {
	var rawData map[string]interface{}
	if err := json.Unmarshal([]byte(decryptedContent), &rawData); err != nil {
		return fmt.Errorf("failed to parse disband request: %w", err)
	}

	groupID, ok := rawData["groupId"].(string)
	if !ok || groupID == "" {
		return fmt.Errorf("invalid disband request: missing groupId")
	}

	s.Log.Infof("Processing disband for group %s from event ID: %s", groupID, evt.ID)

	// Permission: require admin (no initial creation fallback for 20041)
	store := s.relay.Storage(ctx)
	postgresBackend, ok := store.(*postgresql.PostgresBackend)
	if !ok {
		return errUnsupportedGroupMgmtBackend
	}
	// If group has admins, require sender to be admin; otherwise allow (fresh group creation case)
	hasAdmin, errGA := s.groupHasAnyAdmin(ctx, postgresBackend, groupID)
	if errGA != nil {
		s.Log.Warningf("20041: failed to check admin presence for group %s: %v; allowing as fresh group", groupID, errGA)
	}
	if hasAdmin {
		isOwner, errIsOwner := s.isOwner(ctx, postgresBackend, groupID, evt.PubKey)
		if errIsOwner != nil {
			return fmt.Errorf("group disband permission check failed: %w", errIsOwner)
		}
		if !isOwner {
			return fmt.Errorf("forbidden: 3046-disband requires owner of group %s", groupID)
		}
	}

	approvalData := GroupApprovalData{
		GroupID:                groupID,
		IsJoinApprovalRequired: true,
		CreatedAt:              evt.CreatedAt.Time(),
		UpdatedAt:              time.Now(),
		IsDissolved:            true,
	}

	err := s.upsertGroupApprovalInline(ctx, postgresBackend, approvalData)
	if err != nil {
		s.Log.Errorf("Failed to update disband status for group %s: %v", groupID, err)
		return err
	}

	s.Log.Infof("Successfully updated disband status for group %s", groupID)
	return nil
}

// handleMemberAdditionEvent processes 3047 events (member addition)
func (s *Server) handleMemberAdditionEvent(ctx context.Context, evt *nostr.Event, botPrivateKey string) error {
	s.Log.Infof("Processing member addition event ID: %s from %s", evt.ID, evt.PubKey)

	// Decrypt the content
	decryptedContent, err := s.decryptMessage(evt.Content, botPrivateKey, evt.PubKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt member addition content: %w", err)
	}

	s.Log.Infof("Decrypted content: %s", decryptedContent)

	// Parse the member addition request (same structure as session key rotation)
	var request MemberAdditionRequest
	if err := json.Unmarshal([]byte(decryptedContent), &request); err != nil {
		return fmt.Errorf("failed to parse member addition request: %w", err)
	}

	// Use PostgresBackend to update group membership
	store := s.relay.Storage(ctx)
	if postgresBackend, ok := store.(*postgresql.PostgresBackend); ok {
		// if type exists and is "leave", handle member leaving
		if request.Type == "leave" {
			// Handle member leaving
			s.Log.Infof("Member leaving for group %s, %d members to remove",
				request.GroupID, len(request.Members))
			// check the user is a member and they is not the owner and the genpubkey in the request matches the latest genpubkey
			if isMember, err := s.isMember(ctx, postgresBackend, request.GroupID, evt.PubKey); err != nil {
				return fmt.Errorf("failed to verify sender membership: %w", err)
			} else if !isMember {
				return fmt.Errorf("forbidden: sender %s is not a member of group %s", evt.PubKey, request.GroupID)
			}
			if isOwner, err := s.isOwner(ctx, postgresBackend, request.GroupID, evt.PubKey); err != nil {
				return fmt.Errorf("failed to verify sender ownership: %w", err)
			} else if isOwner {
				return fmt.Errorf("forbidden: owner %s cannot leave group %s", evt.PubKey, request.GroupID)
			}
			// check latest genpubkey
			if latestGenPubkey, err := s.getGroupGenPubkey(ctx, postgresBackend, request.GroupID); err != nil {
				return fmt.Errorf("failed to get latest gen pubkey for group %s: %w", request.GroupID, err)
			} else if latestGenPubkey != request.GenPubkey {
				return fmt.Errorf("forbidden: gen pubkey mismatch for group %s", request.GroupID)
			}

			// Check if the group members record exists in group_current_members table, if not, pre process the members from group_memberships to group_current_members
			if err := s.preprocessCurrentMembersInline(ctx, postgresBackend, request.GroupID); err != nil {
				return fmt.Errorf("failed to preprocess current members for group %s: %w", request.GroupID, err)
			}
			// if exists, delete the member from group_current_members and update updated_at field for the group
			if err := s.updateGroupCurrentMembersInline(ctx, postgresBackend, request.GroupID, evt.PubKey, nil, nil); err != nil {
				return fmt.Errorf("failed to remove member %s from group %s: %w", evt.PubKey, request.GroupID, err)
			}
			s.Log.Infof("Successfully removed member %s from group %s", evt.PubKey, request.GroupID)

		} else {
			// Handle member addition
			s.Log.Infof("Member addition for group %s, %d members to add",
				request.GroupID, len(request.Members))

			// Determine the admin pubkey (encryptPubkey or sender)
			encryptKey := request.EncryptPubkey
			if encryptKey == "" {
				encryptKey = evt.PubKey
			}

			// Permission: if group requires join approval, adding members via 3047 is forbidden
			required, errJA := s.isJoinApprovalRequired(ctx, postgresBackend, request.GroupID)
			if errJA != nil {
				// Align with bot behavior: treat as not required on error, but log
				s.Log.Warningf("join approval check failed for group %s: %v; treating as not required", request.GroupID, errJA)
			} else if required {
				return fmt.Errorf("forbidden: group %s requires join approval; cannot add members via 3047", request.GroupID)
			}

			// Additional check: sender must be an existing member
			senderIsMember, errSM := s.isMember(ctx, postgresBackend, request.GroupID, evt.PubKey)
			if errSM != nil {
				return fmt.Errorf("failed to verify sender membership: %w", errSM)
			}
			if !senderIsMember {
				return fmt.Errorf("forbidden: sender %s is not a member of group %s", evt.PubKey, request.GroupID)
			}

			// Process all new members
			for _, member := range request.Members {
				if len(member) < 2 {
					s.Log.Warningf("Invalid member data: %v", member)
					continue
				}

				memberPubKey := member[0]
				encryptedKey := member[1]

				// Skip if already a current member
				already, err := s.isMember(ctx, postgresBackend, request.GroupID, memberPubKey)
				if err != nil {
					s.Log.Errorf("Failed to check existing membership for %s in %s: %v", memberPubKey, request.GroupID, err)
					continue
				}
				if already {
					s.Log.Infof("Member %s already in group %s, skipping", memberPubKey, request.GroupID)
					continue
				}

				membershipData := GroupMembershipData{
					EventID:             evt.ID,
					GroupID:             request.GroupID,
					MemberPubkey:        memberPubKey,
					EncryptedSessionKey: encryptedKey,
					AdminPubkey:         encryptKey,
					GenPubkey:           request.GenPubkey,
					PreGenPubkey:        &request.PreGenPubkey,
					Latest:              false, // Will be set correctly after all inserts
					DecryptType:         0,     // Admin-generated
					CreatedAt:           request.CreatedAt,
					InsertedAt:          time.Now().Unix(),
				}

				upsertErr := s.upsertGroupMembershipInline(ctx, postgresBackend, membershipData)
				if upsertErr != nil {
					s.Log.Errorf("Failed to add member %s to group %s: %v",
						memberPubKey, request.GroupID, upsertErr)
					// Continue processing other members
					continue
				}

				s.Log.Infof("Successfully added member %s to group %s",
					memberPubKey, request.GroupID)
			}

			// Always update latest flags to ensure consistency
			err = s.updateLatestFlagsForGroupMembership(ctx, postgresBackend, request.GroupID)
			if err != nil {
				s.Log.Errorf("Failed to update latest flags for group %s: %v", request.GroupID, err)
				return err
			}
		}
		return nil
	}

	return fmt.Errorf("group management requires PostgreSQL backend")
}

// upsertGroupMembershipInline inserts or updates group membership data inline
func (s *Server) upsertGroupMembershipInline(ctx context.Context, backend *postgresql.PostgresBackend, data GroupMembershipData) error {
	s.Log.Infof("Starting upsertGroupMembershipInline for member %s in group %s", data.MemberPubkey, data.GroupID)

	// Schema is already ensured in handleGroupManagementEventInline, skip here to avoid context cancellation
	s.Log.Infof("Schema already ensured, proceeding with insert/update for member %s", data.MemberPubkey)

	schema := s.getGroupSchema()
	query := fmt.Sprintf(`
        INSERT INTO %s.group_memberships (
            event_id, group_id, member_pubkey, encrypted_session_key, admin_pubkey, 
            gen_pubkey, pre_gen_pubkey, latest, decrypt_type, created_at, inserted_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, to_timestamp($10::double precision), to_timestamp($11::double precision))
        ON CONFLICT (event_id, group_id, member_pubkey)
        DO UPDATE SET
            encrypted_session_key = EXCLUDED.encrypted_session_key,
            admin_pubkey = EXCLUDED.admin_pubkey,
            gen_pubkey = EXCLUDED.gen_pubkey,
            pre_gen_pubkey = EXCLUDED.pre_gen_pubkey,
            latest = EXCLUDED.latest,
            decrypt_type = EXCLUDED.decrypt_type,
            inserted_at = EXCLUDED.inserted_at
        `, schema)

	args := []interface{}{
		data.EventID,
		data.GroupID,
		data.MemberPubkey,
		data.EncryptedSessionKey,
		data.AdminPubkey,
		data.GenPubkey,
		data.PreGenPubkey,
		data.Latest,
		data.DecryptType,
		data.CreatedAt,
		data.InsertedAt,
	}

	s.Log.Infof("Prepared INSERT query for member %s with %d args", data.MemberPubkey, len(args))

	// Check if we have a transaction in context
	if tx, hasTx := eventstore.TxFrom(ctx); hasTx {
		s.Log.Infof("Executing INSERT with transaction for member %s", data.MemberPubkey)
		_, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			s.Log.Errorf("INSERT failed with transaction for member %s: %v", data.MemberPubkey, err)
			return err
		}
		s.Log.Infof("INSERT succeeded with transaction for member %s", data.MemberPubkey)
		return nil
	}

	// No transaction, use direct DB connection
	s.Log.Infof("Executing INSERT without transaction for member %s", data.MemberPubkey)
	_, err := backend.DB.ExecContext(ctx, query, args...)
	if err != nil {
		s.Log.Errorf("INSERT failed without transaction for member %s: %v", data.MemberPubkey, err)
		return err
	}
	s.Log.Infof("INSERT succeeded without transaction for member %s", data.MemberPubkey)
	return nil
}

// upsertAdminKeyInline inserts or updates admin key data inline
func (s *Server) upsertAdminKeyInline(ctx context.Context, backend *postgresql.PostgresBackend, data AdminKeyData) error {
	// Schema is already ensured in handleGroupManagementEventInline, skip here to avoid context cancellation

	schema := s.getGroupSchema()
	query := fmt.Sprintf(`
        INSERT INTO %s.admin_keys (
            event_id, group_id, owner_pubkey, user_pubkey, encrypted_private_key, 
            latest, created_at, inserted_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7::double precision), to_timestamp($8::double precision))
        ON CONFLICT (event_id, group_id, user_pubkey)
        DO UPDATE SET
            owner_pubkey = EXCLUDED.owner_pubkey,
            encrypted_private_key = EXCLUDED.encrypted_private_key,
            latest = EXCLUDED.latest,
            inserted_at = EXCLUDED.inserted_at
        `, schema)

	args := []interface{}{
		data.EventID,
		data.GroupID,
		data.OwnerPubkey,
		data.UserPubkey,
		data.EncryptedPrivateKey,
		data.Latest,
		data.CreatedAt,
		data.InsertedAt,
	}

	// Check if we have a transaction in context
	if tx, hasTx := eventstore.TxFrom(ctx); hasTx {
		_, err := tx.ExecContext(ctx, query, args...)
		return err
	}

	// No transaction, use direct DB connection
	_, err := backend.DB.ExecContext(ctx, query, args...)
	return err
}

// updateGroupCurrentMembersInline refreshes group_current_members either by removing a single member
// (memberToLeave != "") or by overwriting the snapshot when a newer 3046 arrives (snapshotCreatedAt != nil).
func (s *Server) updateGroupCurrentMembersInline(
	ctx context.Context,
	backend *postgresql.PostgresBackend,
	groupID string,
	memberToLeave string,
	snapshotCreatedAt *time.Time,
	snapshotMembers [][]string,
) error {
	tx, hasTx := eventstore.TxFrom(ctx)
	if !hasTx {
		return fmt.Errorf("transaction required for updating current members")
	}

	schema := s.getGroupSchema()

	// Snapshot refresh path (3046)
	if snapshotCreatedAt != nil {
		snapshotTime := snapshotCreatedAt.UTC()

		maxQuery := fmt.Sprintf(`SELECT MAX(created_at) FROM %s.group_current_members WHERE group_id = $1`, schema)
		var latest sql.NullTime
		if err := tx.QueryRowContext(ctx, maxQuery, groupID).Scan(&latest); err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("failed to read current snapshot timestamp for group %s: %w", groupID, err)
		}

		if latest.Valid && !snapshotTime.After(latest.Time) {
			s.Log.Infof("Skip refreshing group_current_members for %s; snapshot %s is not newer than %s", groupID, snapshotTime, latest.Time)
		} else {
			deleteQuery := fmt.Sprintf(`DELETE FROM %s.group_current_members WHERE group_id = $1`, schema)
			if _, err := tx.ExecContext(ctx, deleteQuery, groupID); err != nil {
				return fmt.Errorf("failed to clear members for group %s: %w", groupID, err)
			}

			if len(snapshotMembers) == 0 {
				return nil
			}

			now := time.Now().UTC()
			seen := make(map[string]struct{}, len(snapshotMembers))
			values := make([]string, 0, len(snapshotMembers))
			args := make([]interface{}, 0, len(snapshotMembers)*4)
			valid := 0
			for _, member := range snapshotMembers {
				if len(member) == 0 {
					continue
				}
				memberPubKey := strings.TrimSpace(member[0])
				if memberPubKey == "" {
					continue
				}
				if _, exists := seen[memberPubKey]; exists {
					continue
				}
				seen[memberPubKey] = struct{}{}
				offset := valid * 4
				values = append(values, fmt.Sprintf("($%d,$%d,$%d,$%d)", offset+1, offset+2, offset+3, offset+4))
				args = append(args, groupID, memberPubKey, snapshotTime, now)
				valid++
			}

			if valid == 0 {
				return nil
			}

			insertQuery := fmt.Sprintf(`
				INSERT INTO %s.group_current_members (group_id, member_pubkey, created_at, updated_at)
				VALUES %s
			`, schema, strings.Join(values, ","))
			if _, err := tx.ExecContext(ctx, insertQuery, args...); err != nil {
				return fmt.Errorf("failed to insert refreshed members for group %s: %w", groupID, err)
			}
			return nil
		}
	}

	// Single member removal path (3047 leave)
	if memberToLeave == "" {
		return nil
	}

	deleteQuery := fmt.Sprintf(`
		DELETE FROM %s.group_current_members
		WHERE group_id = $1 AND member_pubkey = $2
	`, schema)
	if _, err := tx.ExecContext(ctx, deleteQuery, groupID, memberToLeave); err != nil {
		return fmt.Errorf("failed to delete member %s from group %s: %w", memberToLeave, groupID, err)
	}

	updateQuery := fmt.Sprintf(`
		UPDATE %s.group_current_members
		SET updated_at = NOW()
		WHERE group_id = $1
	`, schema)
	if _, err := tx.ExecContext(ctx, updateQuery, groupID); err != nil {
		return fmt.Errorf("failed to update updated_at for group %s: %w", groupID, err)
	}

	return nil
}

// ensureGroupMembershipsSchemaInline ensures the group_memberships table exists with correct schema
var groupSchemaOnce sync.Once

func (s *Server) ensureGroupMembershipsSchemaInline(ctx context.Context, backend *postgresql.PostgresBackend) error {
	// Ensure schema only once per process
	var onceErr error
	groupSchemaOnce.Do(func() {
		// Create a separate context for schema operations to avoid cancellation issues
		// Schema creation should not be interrupted by transaction timeouts
		schemaCtx := context.Background()

		// Schema creation must be executed immediately and not wait for outer transaction commit
		// Use direct DB connection instead of transaction for schema operations
		schema := s.getGroupSchema()
		statements := []string{
			fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %s`, schema),

			fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.group_memberships (
                id SERIAL PRIMARY KEY,
                event_id VARCHAR(64) NOT NULL,
                group_id VARCHAR(64) NOT NULL,
                member_pubkey VARCHAR(64) NOT NULL,
                encrypted_session_key TEXT NOT NULL,
                admin_pubkey VARCHAR(64) NOT NULL,
                gen_pubkey VARCHAR(64) NOT NULL DEFAULT 'default_value',
                pre_gen_pubkey VARCHAR(64),
                latest BOOLEAN NOT NULL DEFAULT false,
                decrypt_type INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL,
                inserted_at TIMESTAMPTZ NOT NULL,
                UNIQUE(event_id, group_id, member_pubkey)
            )`, schema),

			fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_group_memberships_event_group_member ON %s.group_memberships(event_id, group_id, member_pubkey)`, schema),
			fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_group_memberships_query ON %s.group_memberships(member_pubkey, group_id, created_at, admin_pubkey, encrypted_session_key, decrypt_type)`, schema),
			fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_group_id_latest_member_pubkey ON %s.group_memberships(group_id, latest, member_pubkey)`, schema),

			fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.admin_keys (
                id SERIAL PRIMARY KEY,
                event_id VARCHAR(64) NOT NULL,
                group_id VARCHAR(64) NOT NULL,
                owner_pubkey VARCHAR(64) NOT NULL,
                user_pubkey VARCHAR(64) NOT NULL,
                encrypted_private_key TEXT NOT NULL,
                latest BOOLEAN NOT NULL DEFAULT false,
                created_at TIMESTAMPTZ NOT NULL,
                inserted_at TIMESTAMPTZ NOT NULL,
                UNIQUE(event_id, group_id, user_pubkey)
            )`, schema),

			fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_admin_keys_event_group_user ON %s.admin_keys(event_id, group_id, user_pubkey)`, schema),

			fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.group_approval_status (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
                group_id VARCHAR NOT NULL,
                is_join_approval_required BOOLEAN DEFAULT false NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                CONSTRAINT group_approval_status_pkey PRIMARY KEY (id)
            )`, schema),

			fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS group_approval_status_group_id_key ON %s.group_approval_status USING btree (group_id)`, schema),

			fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.member_alias (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
                group_id VARCHAR NOT NULL,
                member_pubkey VARCHAR NOT NULL,
                alias VARCHAR NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                CONSTRAINT member_alias_pkey PRIMARY KEY (id)
            )`, schema),

			fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS memberalias_group_id_member_pubkey ON %s.member_alias USING btree (group_id, member_pubkey)`, schema),
		}

		// Always use direct DB connection for schema operations to ensure immediate effect
		// Use a clean context to avoid cancellation issues
		for i, stmt := range statements {
			if _, err := backend.DB.ExecContext(schemaCtx, stmt); err != nil {
				s.Log.Errorf("Failed to execute schema statement %d: %s, error: %v", i+1, stmt, err)
				onceErr = fmt.Errorf("failed to execute schema statement %d: %w", i+1, err)
				return
			}
			s.Log.Infof("Successfully executed schema statement %d", i+1)
		}

		s.Log.Infof("Successfully ensured group management schema exists")
	})

	return onceErr
}

// decryptMessage decrypts NIP-04 or NIP-44 encrypted messages
func (s *Server) decryptMessage(encryptedContent, botPrivateKey, senderPubKey string) (string, error) {
	// Require encrypted content (NIP-04 or NIP-44)
	if !strings.Contains(encryptedContent, "?iv=") && !strings.HasPrefix(encryptedContent, "nip44_") {
		return "", fmt.Errorf("invalid content: expected encrypted payload (nip04 or nip44)")
	}

	// Try NIP-04 decryption first (most common in group_bot)
	if strings.Contains(encryptedContent, "?iv=") {
		sharedKey, err := nip04.ComputeSharedSecret(senderPubKey, botPrivateKey)
		if err != nil {
			return "", fmt.Errorf("failed to compute shared secret: %w", err)
		}

		decrypted, err := nip04.Decrypt(encryptedContent, sharedKey)
		if err == nil {
			return decrypted, nil
		}
		s.Log.Warningf("NIP-04 decryption failed: %v", err)
	}

	// Try NIP-44 decryption if NIP-04 fails
	if strings.HasPrefix(encryptedContent, "nip44_") {
		encryptedData := encryptedContent[6:] // Remove "nip44_" prefix
		conversationKey, err := nip44.GenerateConversationKey(senderPubKey, botPrivateKey)
		if err != nil {
			return "", fmt.Errorf("failed to generate NIP-44 conversation key: %w", err)
		}
		decrypted, err := nip44.Decrypt(encryptedData, conversationKey)
		if err == nil {
			return decrypted, nil
		}
		s.Log.Warningf("NIP-44 decryption failed: %v", err)
	}

	return "", fmt.Errorf("failed to decrypt message with both NIP-04 and NIP-44")
}

// handleIsShareableEvent processes 20041 events (group shareable status)
func (s *Server) handleIsShareableEvent(ctx context.Context, evt *nostr.Event, botPrivateKey string) error {
	s.Log.Infof("Processing 20041 (is_shareable) event ID: %s from %s", evt.ID, evt.PubKey)

	// Decrypt the content using NIP-44
	decryptedContent, err := s.decryptMessageWithNIP44(evt.Content, botPrivateKey, evt.PubKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt 20041 content: %w", err)
	}

	s.Log.Infof("Decrypted 20041 content: %s", decryptedContent)

	var request IsShareableRequest
	if err := json.Unmarshal([]byte(decryptedContent), &request); err != nil {
		return fmt.Errorf("failed to parse is_shareable request: %w", err)
	}

	// Permission: require admin (no initial creation fallback for 20041)
	store := s.relay.Storage(ctx)
	postgresBackend, ok := store.(*postgresql.PostgresBackend)
	if !ok {
		return errUnsupportedGroupMgmtBackend
	}
	// If group has admins, require sender to be admin; otherwise allow (fresh group creation case)
	hasAdmin, errGA := s.groupHasAnyAdmin(ctx, postgresBackend, request.GroupID)
	if errGA != nil {
		s.Log.Warningf("20041: failed to check admin presence for group %s: %v; allowing as fresh group", request.GroupID, errGA)
	}
	if hasAdmin {
		okAdmin, errAdmin := s.isAdmin(ctx, postgresBackend, request.GroupID, evt.PubKey)
		if errAdmin != nil {
			return fmt.Errorf("permission check failed: %w", errAdmin)
		}
		if !okAdmin {
			return fmt.Errorf("forbidden: 20041 requires admin of group %s", request.GroupID)
		}
	}

	// Like group_bot, don't store to database, just publish a 32040 event
	err = s.publishShareableStatusEvent(ctx, request.GroupID, request.IsShareable, botPrivateKey)
	if err != nil {
		s.Log.Errorf("Failed to publish shareable status event for group %s: %v", request.GroupID, err)
		return err
	}

	s.Log.Infof("Successfully published shareable status event for group %s (shareable: %v)", request.GroupID, request.IsShareable)
	return nil
}

// handleJoinApprovalEvent processes 20042 events (group join approval status)
func (s *Server) handleJoinApprovalEvent(ctx context.Context, evt *nostr.Event, botPrivateKey string) error {
	s.Log.Infof("Processing 20042 (join_approval) event ID: %s from %s", evt.ID, evt.PubKey)

	// Decrypt the content using NIP-44
	decryptedContent, err := s.decryptMessageWithNIP44(evt.Content, botPrivateKey, evt.PubKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt 20042 content: %w", err)
	}

	s.Log.Infof("Decrypted 20042 content: %s", decryptedContent)

	var request JoinApprovalRequest
	if err := json.Unmarshal([]byte(decryptedContent), &request); err != nil {
		return fmt.Errorf("failed to parse join_approval request: %w", err)
	}

	store := s.relay.Storage(ctx)
	postgresBackend, ok := store.(*postgresql.PostgresBackend)
	if !ok {
		return errUnsupportedGroupMgmtBackend
	}

	isDissolved, errStatus := s.currentDisbandStatus(ctx, postgresBackend, request.GroupID)
	if errStatus != nil {
		s.Log.Warningf("Failed to load disband status for group %s: %v; defaulting to false", request.GroupID, errStatus)
	}

	approvalData := GroupApprovalData{
		GroupID:                request.GroupID,
		IsJoinApprovalRequired: request.IsJoinApprovalRequired,
		CreatedAt:              evt.CreatedAt.Time(),
		UpdatedAt:              time.Now(),
		IsDissolved:            isDissolved,
	}

	err = s.upsertGroupApprovalInline(ctx, postgresBackend, approvalData)
	if err != nil {
		s.Log.Errorf("Failed to update join approval status for group %s: %v", request.GroupID, err)
		return err
	}

	s.Log.Infof("Successfully updated join approval status for group %s to %v", request.GroupID, request.IsJoinApprovalRequired)
	return nil
}

// handleAliasEvent processes 39304 events (member alias)
func (s *Server) handleAliasEvent(ctx context.Context, evt *nostr.Event, botPrivateKey string) error {
	s.Log.Infof("Processing 39304 (alias) event ID: %s from %s", evt.ID, evt.PubKey)

	// Extract group ID from event tags
	var groupID string
	for _, tag := range evt.Tags {
		if len(tag) >= 2 && tag[0] == "d" {
			groupID = tag[1]
			break
		}
	}
	if groupID == "" {
		return fmt.Errorf("no group ID found in event tags")
	}

	// Decrypt the alias using NIP-04
	decryptedAlias, err := s.decryptMessage(evt.Content, botPrivateKey, evt.PubKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt alias content: %w", err)
	}

	// Permission: require member of the group
	store := s.relay.Storage(ctx)
	postgresBackend, ok := store.(*postgresql.PostgresBackend)
	if !ok {
		return errUnsupportedGroupMgmtBackend
	}
	okMember, errMember := s.isMember(ctx, postgresBackend, groupID, evt.PubKey)
	if errMember != nil {
		return fmt.Errorf("permission check failed: %w", errMember)
	}
	if !okMember {
		return fmt.Errorf("forbidden: 39304 requires group member of %s", groupID)
	}

	s.Log.Infof("Decrypted alias for group %s: %s", groupID, decryptedAlias)

	aliasData := MemberAliasData{
		GroupID:      groupID,
		MemberPubkey: evt.PubKey,
		Alias:        decryptedAlias,
		CreatedAt:    evt.CreatedAt.Time(),
	}

	err = s.upsertMemberAliasInline(ctx, postgresBackend, aliasData)
	if err != nil {
		s.Log.Errorf("Failed to update alias for member %s in group %s: %v", evt.PubKey, groupID, err)
		return err
	}

	s.Log.Infof("Successfully updated alias for member %s in group %s to %s", evt.PubKey, groupID, decryptedAlias)

	// After updating the alias, publish the updated alias list for the group (like group_bot does)
	err = s.publishAliasListForGroup(ctx, postgresBackend, groupID, botPrivateKey)
	if err != nil {
		s.Log.Errorf("Failed to publish alias list for group %s: %v", groupID, err)
		// Don't return error here as the alias was successfully stored
		// This is just a notification that may fail
	}

	return nil
}

// upsertGroupApprovalInline inserts or updates group approval status
func (s *Server) upsertGroupApprovalInline(ctx context.Context, backend *postgresql.PostgresBackend, data GroupApprovalData) error {
	schema := s.getGroupSchema()
	query := fmt.Sprintf(`
        INSERT INTO %s.group_approval_status (
            group_id, is_join_approval_required, created_at, updated_at, is_dissolved
        )
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (group_id)
        DO UPDATE SET
            is_join_approval_required = EXCLUDED.is_join_approval_required,
            updated_at = EXCLUDED.updated_at,
            is_dissolved = EXCLUDED.is_dissolved
    `, schema)

	args := []interface{}{
		data.GroupID,
		data.IsJoinApprovalRequired,
		data.CreatedAt,
		data.UpdatedAt,
		data.IsDissolved,
	}

	// Check if we have a transaction in context
	if tx, hasTx := eventstore.TxFrom(ctx); hasTx {
		_, err := tx.ExecContext(ctx, query, args...)
		return err
	}

	// No transaction, use direct DB connection
	_, err := backend.DB.ExecContext(ctx, query, args...)
	return err
}

// upsertMemberAliasInline inserts or updates member alias
func (s *Server) upsertMemberAliasInline(ctx context.Context, backend *postgresql.PostgresBackend, data MemberAliasData) error {
	schema := s.getGroupSchema()
	query := fmt.Sprintf(`
        INSERT INTO %s.member_alias (
            group_id, member_pubkey, alias, created_at
        )
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (group_id, member_pubkey)
        DO UPDATE SET
            alias = EXCLUDED.alias,
            created_at = EXCLUDED.created_at
        WHERE EXCLUDED.created_at > %s.member_alias.created_at
    `, schema, schema)

	args := []interface{}{
		data.GroupID,
		data.MemberPubkey,
		data.Alias,
		data.CreatedAt,
	}

	// Check if we have a transaction in context
	if tx, hasTx := eventstore.TxFrom(ctx); hasTx {
		_, err := tx.ExecContext(ctx, query, args...)
		return err
	}

	// No transaction, use direct DB connection
	_, err := backend.DB.ExecContext(ctx, query, args...)
	return err
}

// decryptMessageWithNIP44 decrypts NIP-44 encrypted messages specifically
func (s *Server) decryptMessageWithNIP44(encryptedContent, botPrivateKey, senderPubKey string) (string, error) {
	conversationKey, err := nip44.GenerateConversationKey(senderPubKey, botPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate NIP-44 conversation key: %w", err)
	}

	decrypted, err := nip44.Decrypt(encryptedContent, conversationKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt with NIP-44: %w", err)
	}

	return decrypted, nil
}

// publishAliasListForGroup publishes a 39305 event with all aliases for the group
func (s *Server) publishAliasListForGroup(ctx context.Context, backend *postgresql.PostgresBackend, groupID, botPrivateKey string) error {
	// Get all aliases for the group from database
	aliases, err := s.getAllAliasesForGroup(ctx, backend, groupID)
	if err != nil {
		return fmt.Errorf("failed to get aliases for group %s: %w", groupID, err)
	}

	// Get the group's genPubkey
	genPubkey, err := s.getGroupGenPubkey(ctx, backend, groupID)
	if err != nil {
		return fmt.Errorf("failed to get genPubkey for group %s: %w", groupID, err)
	}

	// Prepare the alias list content
	aliasList := make([][]string, 0, len(aliases))
	for _, alias := range aliases {
		aliasList = append(aliasList, []string{alias.MemberPubkey, alias.Alias})
	}

	content := map[string]interface{}{
		"groupId": groupID,
		"alias":   aliasList,
	}

	contentBytes, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("failed to marshal alias list content: %w", err)
	}

	// Encrypt content with NIP-44
	encryptedContent, err := s.encryptContentWithNIP44(string(contentBytes), botPrivateKey, genPubkey)
	if err != nil {
		return fmt.Errorf("failed to encrypt alias list content: %w", err)
	}

	// Get bot public key
	botPubkey, err := nostr.GetPublicKey(botPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to get bot public key: %w", err)
	}

	// Create the 39305 event
	aliasListEvent := nostr.Event{
		PubKey:    botPubkey,
		CreatedAt: nostr.Now(),
		Kind:      39305,
		Tags: nostr.Tags{
			{"d", genPubkey},
			{"p", genPubkey},
		},
		Content: encryptedContent,
	}

	// Sign the event
	if err := aliasListEvent.Sign(botPrivateKey); err != nil {
		return fmt.Errorf("failed to sign alias list event: %w", err)
	}

	// Publish the event through the relay (we need to implement this)
	err = s.publishEventToRelay(ctx, &aliasListEvent)
	if err != nil {
		return fmt.Errorf("failed to publish alias list event: %w", err)
	}

	s.Log.Infof("Successfully published alias list for group %s with %d aliases", groupID, len(aliases))
	return nil
}

// getAllAliasesForGroup retrieves all aliases for a given group
func (s *Server) getAllAliasesForGroup(ctx context.Context, backend *postgresql.PostgresBackend, groupID string) ([]MemberAliasData, error) {
	schema := s.getGroupSchema()
	query := fmt.Sprintf(`
		SELECT group_id, member_pubkey, alias, created_at
		FROM %s.member_alias
		WHERE group_id = $1
		ORDER BY member_pubkey
	`, schema)

	var aliases []MemberAliasData

	// Check if we have a transaction in context
	if tx, hasTx := eventstore.TxFrom(ctx); hasTx {
		rows, err := tx.QueryContext(ctx, query, groupID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var alias MemberAliasData
			err := rows.Scan(&alias.GroupID, &alias.MemberPubkey, &alias.Alias, &alias.CreatedAt)
			if err != nil {
				return nil, err
			}
			aliases = append(aliases, alias)
		}
		return aliases, nil
	}

	// No transaction, use direct DB connection
	rows, err := backend.DB.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var alias MemberAliasData
		err := rows.Scan(&alias.GroupID, &alias.MemberPubkey, &alias.Alias, &alias.CreatedAt)
		if err != nil {
			return nil, err
		}
		aliases = append(aliases, alias)
	}

	return aliases, nil
}

// getGroupGenPubkey retrieves the genPubkey for a group from the latest membership records
func (s *Server) getGroupGenPubkey(ctx context.Context, backend *postgresql.PostgresBackend, groupID string) (string, error) {
	schema := s.getGroupSchema()
	query := fmt.Sprintf(`
		SELECT gen_pubkey
		FROM %s.group_memberships
		WHERE group_id = $1 AND latest = true
		LIMIT 1
	`, schema)

	var genPubkey string

	// Check if we have a transaction in context
	if tx, hasTx := eventstore.TxFrom(ctx); hasTx {
		err := tx.QueryRowContext(ctx, query, groupID).Scan(&genPubkey)
		if err != nil {
			return "", err
		}
	} else {
		// No transaction, use direct DB connection
		err := backend.DB.QueryRowContext(ctx, query, groupID).Scan(&genPubkey)
		if err != nil {
			return "", err
		}
	}

	if genPubkey == "" || genPubkey == "default_value" {
		return "", fmt.Errorf("genPubkey is empty or default for group %s", groupID)
	}

	return genPubkey, nil
}

// encryptContentWithNIP44 encrypts content using NIP-44
func (s *Server) encryptContentWithNIP44(content, botPrivateKey, recipientPubkey string) (string, error) {
	conversationKey, err := nip44.GenerateConversationKey(recipientPubkey, botPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate conversation key: %w", err)
	}

	encrypted, err := nip44.Encrypt(content, conversationKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt content: %w", err)
	}

	return encrypted, nil
}

// publishEventToRelay publishes an event to the relay
func (s *Server) publishEventToRelay(ctx context.Context, evt *nostr.Event) error {
	// Store the event in the relay's storage
	store := s.relay.Storage(ctx)
	if store != nil {
		if err := store.SaveEvent(ctx, evt); err != nil {
			return fmt.Errorf("failed to save event to relay storage: %w", err)
		}
	}

	// Broadcast after commit if inside a transaction; otherwise broadcast now
	if queued := queuePostCommitBroadcast(ctx, evt); !queued {
		s.broadcastEvent(evt)
		// Also propagate to external listeners if supported
		if b, ok := s.relay.(EventBroadcaster); ok {
			b.BroadcastEvent(evt)
		}
	}

	return nil
}

// broadcastEvent broadcasts an event to all connected websocket clients
func (s *Server) broadcastEvent(evt *nostr.Event) {
	// Use the existing relay broadcasting functionality
	BroadcastEvent(evt)
	s.Log.Infof("Broadcasted event %s (kind %d) to connected clients", evt.ID, evt.Kind)
}

// publishShareableStatusEvent publishes a 32040 event with shareable status
func (s *Server) publishShareableStatusEvent(ctx context.Context, groupID string, isShareable bool, botPrivateKey string) error {
	// Create content structure like group_bot does
	contentStruct := struct {
		Shareable bool `json:"shareable"`
	}{
		Shareable: isShareable,
	}

	contentBytes, err := json.Marshal(contentStruct)
	if err != nil {
		return fmt.Errorf("failed to marshal shareable content: %w", err)
	}

	// Get bot public key
	botPubkey, err := nostr.GetPublicKey(botPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to get bot public key: %w", err)
	}

	// Create the 32040 event
	shareableEvent := nostr.Event{
		PubKey:    botPubkey,
		CreatedAt: nostr.Now(),
		Kind:      32040,
		Tags: nostr.Tags{
			{"d", groupID},
		},
		Content: string(contentBytes),
	}

	// Sign the event
	if err := shareableEvent.Sign(botPrivateKey); err != nil {
		return fmt.Errorf("failed to sign shareable event: %w", err)
	}

	// Publish the event through the relay
	err = s.publishEventToRelay(ctx, &shareableEvent)
	if err != nil {
		return fmt.Errorf("failed to publish shareable event: %w", err)
	}

	s.Log.Infof("Successfully published shareable status event for group %s (shareable: %v)", groupID, isShareable)
	return nil
}
