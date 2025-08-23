package relayer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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
	EventID              string `json:"event_id" db:"event_id"`
	GroupID              string `json:"group_id" db:"group_id"`
	MemberPubkey         string `json:"member_pubkey" db:"member_pubkey"`
	EncryptedSessionKey  string `json:"encrypted_session_key" db:"encrypted_session_key"`
	AdminPubkey          string `json:"admin_pubkey" db:"admin_pubkey"`
	GenPubkey            string `json:"gen_pubkey" db:"gen_pubkey"`
	PreGenPubkey         *string `json:"pre_gen_pubkey" db:"pre_gen_pubkey"`
	Latest               bool   `json:"latest" db:"latest"`
	DecryptType          int    `json:"decrypt_type" db:"decrypt_type"`
	CreatedAt            int64  `json:"created_at" db:"created_at"`
	InsertedAt           int64  `json:"inserted_at" db:"inserted_at"`
}

// AdminKeyData represents the data structure for admin keys based on entgo schema
type AdminKeyData struct {
	EventID              string `json:"event_id" db:"event_id"`
	GroupID              string `json:"group_id" db:"group_id"`
	OwnerPubkey          string `json:"owner_pubkey" db:"owner_pubkey"`
	UserPubkey           string `json:"user_pubkey" db:"user_pubkey"`
	EncryptedPrivateKey  string `json:"encrypted_private_key" db:"encrypted_private_key"`
	Latest               bool   `json:"latest" db:"latest"`
	CreatedAt            int64  `json:"created_at" db:"created_at"`
	InsertedAt           int64  `json:"inserted_at" db:"inserted_at"`
}

// SessionKeyRotationRequest represents the structure for 3046 events (gen-key update)
type SessionKeyRotationRequest struct {
	GroupID      string     `json:"groupId"`
	GenPubkey    string     `json:"genPubkey,omitempty"`
	PreGenPubkey *string    `json:"preGenPubkey,omitempty"`
	EncryptPubkey string    `json:"encryptPubkey,omitempty"`
	Members      [][]string `json:"members,omitempty"`
	CreatedAt    int64      `json:"createdAt,omitempty"`
}

// AdminKeyUpdateRequest represents the structure for 3046 events (admin-key update)
type AdminKeyUpdateRequest struct {
	GroupID      string     `json:"groupId"`
	EncryptPubkey string    `json:"encryptPubkey,omitempty"`
	Roles        [][]string `json:"roles,omitempty"`
	CreatedAt    int64      `json:"createdAt,omitempty"`
}

// MemberAdditionRequest represents the structure for 3047 events (same as session key rotation)
type MemberAdditionRequest struct {
	GroupID      string     `json:"groupId"`
	GenPubkey    string     `json:"genPubkey"`
	PreGenPubkey string     `json:"preGenPubkey"`
	EncryptPubkey string    `json:"encryptPubkey"`
	Members      [][]string `json:"members"`
	CreatedAt    int64      `json:"createdAt"`
}

// handleGroupManagementEventInline processes group management events inline
func (s *Server) handleGroupManagementEventInline(ctx context.Context, evt *nostr.Event) error {
	// Get bot private key from relay config
	var botPrivateKey string
	if configProvider, ok := s.relay.(interface{ GetGroupManagementConfig() string }); ok {
		botPrivateKey = configProvider.GetGroupManagementConfig()
	}

	if botPrivateKey == "" {
		return fmt.Errorf("bot private key not configured")
	}

	// Get the PostgreSQL backend first
	store := s.relay.Storage(ctx)
	postgresBackend, ok := store.(*postgresql.PostgresBackend)
	if !ok {
		return fmt.Errorf("group management requires PostgreSQL backend")
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
			} else {
				localTx.Commit()
			}
		}()
	}

	switch evt.Kind {
	case 3046:
		err = s.handleSessionKeyRotationEvent(ctx, evt, botPrivateKey)
	case 3047:
		err = s.handleMemberAdditionEvent(ctx, evt, botPrivateKey)
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

	// Try to determine if this is gen-key update (has members) or admin-key update (has roles)
	var rawData map[string]interface{}
	if err := json.Unmarshal([]byte(decryptedContent), &rawData); err != nil {
		return fmt.Errorf("failed to parse 3046 raw data: %w", err)
	}

	store := s.relay.Storage(ctx)
	postgresBackend, ok := store.(*postgresql.PostgresBackend)
	if !ok {
		return fmt.Errorf("group management requires PostgreSQL backend")
	}

	if members, hasMembers := rawData["members"]; hasMembers && members != nil {
		// This is a gen-key update (session key rotation)
		return s.handleGenKeyUpdate(ctx, evt, decryptedContent, botPrivateKey, postgresBackend)
	} else if roles, hasRoles := rawData["roles"]; hasRoles && roles != nil {
		// This is an admin-key update
		return s.handleAdminKeyUpdate(ctx, evt, decryptedContent, botPrivateKey, postgresBackend)
	} else {
		return fmt.Errorf("unknown 3046 event type: neither members nor roles found")
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
	existingQuery := `SELECT member_pubkey FROM moss_api.group_memberships WHERE event_id = $1 AND group_id = $2`
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

	return nil
}

// updateLatestFlagsForGroupMembership ensures only the records with max created_at have latest=true
func (s *Server) updateLatestFlagsForGroupMembership(ctx context.Context, backend *postgresql.PostgresBackend, groupID string) error {
	tx, hasTx := eventstore.TxFrom(ctx)
	if !hasTx {
		return fmt.Errorf("transaction required for latest flag updates")
	}

	// Find the current maximum created_at and gen_pubkey
	latestQuery := `
		SELECT created_at, gen_pubkey 
		FROM moss_api.group_memberships 
		WHERE group_id = $1 
		ORDER BY created_at DESC, gen_pubkey DESC 
		LIMIT 1
	`
	var maxCreatedAt int64
	var maxGenPubkey string
	err := tx.QueryRowContext(ctx, latestQuery, groupID).Scan(&maxCreatedAt, &maxGenPubkey)
	if err != nil {
		if err == sql.ErrNoRows {
			// No records for this group, nothing to update
			return nil
		}
		return fmt.Errorf("failed to query latest record: %w", err)
	}

	// Reset only the records that are currently latest=true but should not be
	resetLatestQuery := `
		UPDATE moss_api.group_memberships 
		SET latest = false 
		WHERE group_id = $1 AND latest = true 
		AND NOT (created_at = $2 AND gen_pubkey = $3)
	`
	_, err = tx.ExecContext(ctx, resetLatestQuery, groupID, maxCreatedAt, maxGenPubkey)
	if err != nil {
		return fmt.Errorf("failed to reset latest flags: %w", err)
	}

	// Set latest=true for records with the maximum created_at and gen_pubkey that aren't already latest
	setLatestQuery := `
		UPDATE moss_api.group_memberships 
		SET latest = true 
		WHERE group_id = $1 AND created_at = $2 AND gen_pubkey = $3 AND latest = false
	`
	_, err = tx.ExecContext(ctx, setLatestQuery, groupID, maxCreatedAt, maxGenPubkey)
	if err != nil {
		return fmt.Errorf("failed to set latest flags: %w", err)
	}

	s.Log.Infof("Updated latest flags for group %s (max created_at: %d, gen_pubkey: %s)", groupID, maxCreatedAt, maxGenPubkey)
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

	// Find the current maximum created_at
	latestQuery := `
		SELECT MAX(created_at) 
		FROM moss_api.admin_keys 
		WHERE group_id = $1
	`
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
	resetLatestQuery := `
		UPDATE moss_api.admin_keys 
		SET latest = false 
		WHERE group_id = $1 AND latest = true AND created_at != $2
	`
	_, err = tx.ExecContext(ctx, resetLatestQuery, groupID, maxCreatedAt)
	if err != nil {
		return fmt.Errorf("failed to reset admin key latest flags: %w", err)
	}

	// Set latest=true for records with the maximum created_at that aren't already latest
	setLatestQuery := `
		UPDATE moss_api.admin_keys 
		SET latest = true 
		WHERE group_id = $1 AND created_at = $2 AND latest = false
	`
	_, err = tx.ExecContext(ctx, setLatestQuery, groupID, maxCreatedAt)
	if err != nil {
		return fmt.Errorf("failed to set admin key latest flags: %w", err)
	}

	s.Log.Infof("Updated latest flags for admin keys in group %s (max created_at: %d)", groupID, maxCreatedAt)
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
		s.Log.Infof("Member addition for group %s, %d members to add", 
			request.GroupID, len(request.Members))

		// Determine the admin pubkey (encryptPubkey or sender)
		encryptKey := request.EncryptPubkey
		if encryptKey == "" {
			encryptKey = evt.PubKey
		}

		// Process all new members
		for _, member := range request.Members {
			if len(member) < 2 {
				s.Log.Warningf("Invalid member data: %v", member)
				continue
			}
			
			memberPubKey := member[0]
			encryptedKey := member[1]

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

			err := s.upsertGroupMembershipInline(ctx, postgresBackend, membershipData)
			if err != nil {
				s.Log.Errorf("Failed to add member %s to group %s: %v", 
					memberPubKey, request.GroupID, err)
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
		
		return nil
	}

	return fmt.Errorf("group management requires PostgreSQL backend")
}

// upsertGroupMembershipInline inserts or updates group membership data inline
func (s *Server) upsertGroupMembershipInline(ctx context.Context, backend *postgresql.PostgresBackend, data GroupMembershipData) error {
	s.Log.Infof("Starting upsertGroupMembershipInline for member %s in group %s", data.MemberPubkey, data.GroupID)
	
	// Schema is already ensured in handleGroupManagementEventInline, skip here to avoid context cancellation
	s.Log.Infof("Schema already ensured, proceeding with insert/update for member %s", data.MemberPubkey)

	query := `
		INSERT INTO moss_api.group_memberships (
			event_id, group_id, member_pubkey, encrypted_session_key, admin_pubkey, 
			gen_pubkey, pre_gen_pubkey, latest, decrypt_type, created_at, inserted_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (event_id, group_id, member_pubkey)
		DO UPDATE SET
			encrypted_session_key = EXCLUDED.encrypted_session_key,
			admin_pubkey = EXCLUDED.admin_pubkey,
			gen_pubkey = EXCLUDED.gen_pubkey,
			pre_gen_pubkey = EXCLUDED.pre_gen_pubkey,
			latest = EXCLUDED.latest,
			decrypt_type = EXCLUDED.decrypt_type,
			inserted_at = EXCLUDED.inserted_at
	`

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

	query := `
		INSERT INTO moss_api.admin_keys (
			event_id, group_id, owner_pubkey, user_pubkey, encrypted_private_key, 
			latest, created_at, inserted_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (event_id, group_id, user_pubkey)
		DO UPDATE SET
			owner_pubkey = EXCLUDED.owner_pubkey,
			encrypted_private_key = EXCLUDED.encrypted_private_key,
			latest = EXCLUDED.latest,
			inserted_at = EXCLUDED.inserted_at
	`

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

// ensureGroupMembershipsSchemaInline ensures the group_memberships table exists with correct schema
func (s *Server) ensureGroupMembershipsSchemaInline(ctx context.Context, backend *postgresql.PostgresBackend) error {
	// Create a separate context for schema operations to avoid cancellation issues
	// Schema creation should not be interrupted by transaction timeouts
	schemaCtx := context.Background()
	
	// Schema creation must be executed immediately and not wait for outer transaction commit
	// Use direct DB connection instead of transaction for schema operations
	statements := []string{
		`CREATE SCHEMA IF NOT EXISTS moss_api`,
		
		`CREATE TABLE IF NOT EXISTS moss_api.group_memberships (
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
			created_at BIGINT NOT NULL,
			inserted_at BIGINT NOT NULL,
			UNIQUE(event_id, group_id, member_pubkey)
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_group_memberships_event_group_member ON moss_api.group_memberships(event_id, group_id, member_pubkey)`,
		`CREATE INDEX IF NOT EXISTS idx_group_memberships_query ON moss_api.group_memberships(member_pubkey, group_id, created_at, admin_pubkey, encrypted_session_key, decrypt_type)`,
		`CREATE INDEX IF NOT EXISTS idx_group_id_latest_member_pubkey ON moss_api.group_memberships(group_id, latest, member_pubkey)`,
		
		`CREATE TABLE IF NOT EXISTS moss_api.admin_keys (
			id SERIAL PRIMARY KEY,
			event_id VARCHAR(64) NOT NULL,
			group_id VARCHAR(64) NOT NULL,
			owner_pubkey VARCHAR(64) NOT NULL,
			user_pubkey VARCHAR(64) NOT NULL,
			encrypted_private_key TEXT NOT NULL,
			latest BOOLEAN NOT NULL DEFAULT false,
			created_at BIGINT NOT NULL,
			inserted_at BIGINT NOT NULL,
			UNIQUE(event_id, group_id, user_pubkey)
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_admin_keys_event_group_user ON moss_api.admin_keys(event_id, group_id, user_pubkey)`,
	}

	// Always use direct DB connection for schema operations to ensure immediate effect
	// Use a clean context to avoid cancellation issues
	for i, stmt := range statements {
		if _, err := backend.DB.ExecContext(schemaCtx, stmt); err != nil {
			s.Log.Errorf("Failed to execute schema statement %d: %s, error: %v", i+1, stmt, err)
			return fmt.Errorf("failed to execute schema statement %d: %w", i+1, err)
		}
		s.Log.Infof("Successfully executed schema statement %d", i+1)
	}

	s.Log.Infof("Successfully ensured group management schema exists")
	return nil
}

// decryptMessage decrypts NIP-04 or NIP-44 encrypted messages
func (s *Server) decryptMessage(encryptedContent, botPrivateKey, senderPubKey string) (string, error) {
	// Check if content is encrypted (should start with encryption indicator)
	if !strings.Contains(encryptedContent, "?iv=") && !strings.HasPrefix(encryptedContent, "nip44_") {
		// Might be plain text, return as is
		return encryptedContent, nil
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
