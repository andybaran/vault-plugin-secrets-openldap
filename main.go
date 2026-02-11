// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
)

const (
	configPath            = "config"
	staticRolePath        = "static-role/"
	staticCredPath        = "static-cred/"
	defaultPasswordLength = 64
	defaultUserAttr       = "cn"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	// Ensure logger is never nil
	logger := conf.Logger
	if logger == nil {
		logger = hclog.NewNullLogger()
	}

	b := &dualLDAPBackend{
		logger: logger,
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Paths: []*framework.Path{
			{
				Pattern: "config",
				Fields: map[string]*framework.FieldSchema{
					"url": {
						Type:        framework.TypeString,
						Description: "LDAP server URL (ldap:// or ldaps://)",
					},
					"binddn": {
						Type:        framework.TypeString,
						Description: "Bind DN for LDAP connection",
					},
					"bindpass": {
						Type:        framework.TypeString,
						Description: "Bind password for LDAP connection",
						DisplayAttrs: &framework.DisplayAttributes{
							Sensitive: true,
						},
					},
					"userdn": {
						Type:        framework.TypeString,
						Description: "Base DN under which to perform user search",
					},
					"userattr": {
						Type:        framework.TypeString,
						Default:     defaultUserAttr,
						Description: "Attribute on user object matching username (default: cn)",
					},
					"username": {
						Type:        framework.TypeString,
						Description: "Username to rotate",
					},
					"rotation_period": {
						Type:        framework.TypeDurationSecond,
						Default:     60,
						Description: "Password rotation period in seconds (default: 60)",
					},
					"password_length": {
						Type:        framework.TypeInt,
						Default:     defaultPasswordLength,
						Description: "Length of generated passwords (default: 64)",
					},
				},
				ExistenceCheck: b.pathConfigExistenceCheck,
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
					logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
					logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
				},
			},
			{
				Pattern: "rotate",
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRotatePassword},
				},
			},
			{
				Pattern: "creds",
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{Callback: b.pathCredsRead},
				},
			},
			{
				Pattern: "static-role/" + framework.GenericNameRegex("name"),
				Fields: map[string]*framework.FieldSchema{
					"name": {
						Type:        framework.TypeString,
						Description: "Name of the static role",
					},
					"username": {
						Type:        framework.TypeString,
						Description: "LDAP username to manage (single-account mode)",
					},
					"username_a": {
						Type:        framework.TypeString,
						Description: "First LDAP username (dual-account mode)",
					},
					"username_b": {
						Type:        framework.TypeString,
						Description: "Second LDAP username (dual-account mode)",
					},
					"dual_account_mode": {
						Type:        framework.TypeBool,
						Default:     false,
						Description: "Enable dual-account rotation mode",
					},
					"grace_period": {
						Type:        framework.TypeDurationSecond,
						Default:     259200,
						Description: "Grace period in seconds before switching accounts (default: 3 days)",
					},
					"rotation_period": {
						Type:        framework.TypeDurationSecond,
						Default:     60,
						Description: "Password rotation period in seconds (default: 60)",
					},
					"password_length": {
						Type:        framework.TypeInt,
						Default:     defaultPasswordLength,
						Description: "Length of generated passwords (default: 64)",
					},
				},
				ExistenceCheck: b.pathStaticRoleExistenceCheck,
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.CreateOperation: &framework.PathOperation{Callback: b.pathStaticRoleWrite},
					logical.UpdateOperation: &framework.PathOperation{Callback: b.pathStaticRoleWrite},
					logical.ReadOperation:   &framework.PathOperation{Callback: b.pathStaticRoleRead},
					logical.DeleteOperation: &framework.PathOperation{Callback: b.pathStaticRoleDelete},
				},
			},
			{
				Pattern: "static-cred/" + framework.GenericNameRegex("name"),
				Fields: map[string]*framework.FieldSchema{
					"name": {
						Type:        framework.TypeString,
						Description: "Name of the static role",
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{Callback: b.pathStaticCredRead},
				},
			},
			{
				Pattern: "rotate-role/" + framework.GenericNameRegex("name"),
				Fields: map[string]*framework.FieldSchema{
					"name": {
						Type:        framework.TypeString,
						Description: "Name of the static role to rotate",
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRotateRole},
				},
			},
			{
				Pattern: "static-role/" + framework.GenericNameRegex("name") + "/state",
				Fields: map[string]*framework.FieldSchema{
					"name": {
						Type:        framework.TypeString,
						Description: "Name of the static role",
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{Callback: b.pathStaticRoleStateRead},
				},
			},
		},
		Secrets: []*framework.Secret{
			{
				Type: "static_cred",
				Revoke: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
					// Static credentials don't need revocation - they're managed by rotation
					return nil, nil
				},
			},
		},
		PeriodicFunc: b.periodicRotation,
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

// periodicRotation runs periodically to check for roles needing password rotation
func (b *dualLDAPBackend) periodicRotation(ctx context.Context, req *logical.Request) error {
	// Get configuration
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return err
	}
	if config == nil {
		// No config yet, nothing to rotate
		return nil
	}

	// List all static roles
	roles, err := req.Storage.List(ctx, staticRolePath)
	if err != nil {
		return err
	}

	// Check each role for rotation
	for _, roleName := range roles {
		role, err := b.getStaticRole(ctx, req.Storage, roleName)
		if err != nil {
			b.logger.Error("failed to get role for periodic rotation", "role", roleName, "error", err)
			continue
		}
		if role == nil {
			continue
		}

		// Handle dual-account roles with state machine
		if role.DualAccountMode {
			// Check if state transition is needed
			if b.shouldTransitionState(ctx, req.Storage, roleName, role) {
				if err := b.transitionRotationState(ctx, req.Storage, config, roleName, role); err != nil {
					b.logger.Error("dual account state transition failed", "role", roleName, "error", err)
					continue
				}
			}

			// Check if rotation is needed for current state
			if b.shouldRotateDualAccount(ctx, req.Storage, roleName, role) {
				b.logger.Info("dual account periodic rotation triggered", "role", roleName)
				if err := b.rotateDualAccountPassword(ctx, req.Storage, config, roleName, role); err != nil {
					b.logger.Error("dual account periodic rotation failed", "role", roleName, "error", err)
					continue
				}
				b.logger.Info("dual account periodic rotation completed", "role", roleName)
			}
		} else {
			// Single-account rotation
			if b.shouldRotateRole(ctx, req.Storage, roleName, role) {
				b.logger.Info("periodic rotation triggered", "role", roleName)
				if err := b.rotateRolePassword(ctx, req.Storage, config, roleName, role); err != nil {
					b.logger.Error("periodic rotation failed", "role", roleName, "error", err)
					continue
				}
				b.logger.Info("periodic rotation completed", "role", roleName)
			}
		}
	}

	return nil
}

// shouldRotateDualAccount checks if a dual-account role's password should be rotated
func (b *dualLDAPBackend) shouldRotateDualAccount(ctx context.Context, storage logical.Storage, roleName string, role *staticRole) bool {
	if !role.DualAccountMode {
		return false
	}

	// Always rotate during grace periods
	if role.RotationState.State == "grace_period_a_to_b" || role.RotationState.State == "grace_period_b_to_a" {
		return true
	}

	// During active periods, check if it's time to pre-generate next password
	now := time.Now()
	stateStart := time.Unix(role.RotationState.StateStartTime, 0)

	// Rotate if we're past 80% through the active period for pre-generation
	percentageElapsed := float64(now.Sub(stateStart).Seconds()) / float64(role.RotationPeriod.Seconds())
	return percentageElapsed > 0.8
}

// shouldRotateRole checks if a role's password should be rotated
func (b *dualLDAPBackend) shouldRotateRole(ctx context.Context, storage logical.Storage, roleName string, role *staticRole) bool {
	// Get the stored password metadata
	entry, err := storage.Get(ctx, staticCredPath+roleName)
	if err != nil || entry == nil {
		// No password stored yet, should rotate
		return true
	}

	var data map[string]interface{}
	if err := entry.DecodeJSON(&data); err != nil {
		return true
	}

	lastRotationUnix, ok := data["last_rotation"].(float64)
	if !ok {
		return true
	}

	lastRotation := time.Unix(int64(lastRotationUnix), 0)
	nextRotation := lastRotation.Add(role.RotationPeriod)

	return time.Now().After(nextRotation)
}

type dualLDAPBackend struct {
	*framework.Backend
	logger hclog.Logger
}

type ldapConfig struct {
	URL            string        `json:"url"`
	BindDN         string        `json:"binddn"`
	BindPassword   string        `json:"bindpass"`
	UserDN         string        `json:"userdn"`
	UserAttr       string        `json:"userattr"`
	Username       string        `json:"username"`
	RotationPeriod time.Duration `json:"rotation_period"`
	PasswordLength int           `json:"password_length"`
}

type dualAccountInfo struct {
	Username         string `json:"username"`
	CurrentPassword  string `json:"current_password"`
	NextPassword     string `json:"next_password"`
	PreviousPassword string `json:"previous_password"`
	Status           string `json:"status"` // "active", "grace_period", "inactive"
	LastRotated      int64  `json:"last_rotated"`
}

type rotationStateInfo struct {
	State              string `json:"state"` // "account_a_active", "grace_period_a_to_b", "account_b_active", "grace_period_b_to_a"
	ActiveAccount      string `json:"active_account"`
	NextAccount        string `json:"next_account"`
	StateStartTime     int64  `json:"state_start_time"`
	GracePeriodEndTime int64  `json:"grace_period_end_time"`
}

type staticRole struct {
	// Existing fields - kept for backward compatibility
	Username       string        `json:"username"`
	RotationPeriod time.Duration `json:"rotation_period"`
	PasswordLength int           `json:"password_length"`

	// NEW: Dual account support
	DualAccountMode  bool              `json:"dual_account_mode"`
	AccountA         dualAccountInfo   `json:"account_a"`
	AccountB         dualAccountInfo   `json:"account_b"`
	CurrentActive    string            `json:"current_active"` // "account_a" or "account_b"
	LastRotationTime int64             `json:"last_rotation_time"`
	GracePeriod      time.Duration     `json:"grace_period"`
	RotationState    rotationStateInfo `json:"rotation_state"`
}

func (b *dualLDAPBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return config != nil, nil
}

func (b *dualLDAPBackend) pathStaticRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	name := data.Get("name").(string)
	if name == "" {
		return false, nil
	}
	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *dualLDAPBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	defer func() {
		if r := recover(); r != nil {
			b.logger.Error("panic in pathConfigWrite", "panic", r)
		}
	}()

	b.logger.Debug("pathConfigWrite called")

	// Get values with safe type assertions
	url, ok := data.GetOk("url")
	if !ok || url.(string) == "" {
		return logical.ErrorResponse("url is required"), nil
	}

	binddn, ok := data.GetOk("binddn")
	if !ok || binddn.(string) == "" {
		return logical.ErrorResponse("binddn is required"), nil
	}

	bindpass, ok := data.GetOk("bindpass")
	if !ok || bindpass.(string) == "" {
		return logical.ErrorResponse("bindpass is required"), nil
	}

	userdn, ok := data.GetOk("userdn")
	if !ok || userdn.(string) == "" {
		return logical.ErrorResponse("userdn is required"), nil
	}

	username, ok := data.GetOk("username")
	if !ok || username.(string) == "" {
		return logical.ErrorResponse("username is required"), nil
	}

	// Get optional fields with defaults
	userattr := data.Get("userattr").(string)
	if userattr == "" {
		userattr = defaultUserAttr
	}

	rotationPeriod := data.Get("rotation_period").(int)
	if rotationPeriod == 0 {
		rotationPeriod = 60
	}

	passwordLength := data.Get("password_length").(int)
	if passwordLength == 0 {
		passwordLength = defaultPasswordLength
	}

	config := &ldapConfig{
		URL:            url.(string),
		BindDN:         binddn.(string),
		BindPassword:   bindpass.(string),
		UserDN:         userdn.(string),
		UserAttr:       userattr,
		Username:       username.(string),
		RotationPeriod: time.Duration(rotationPeriod) * time.Second,
		PasswordLength: passwordLength,
	}

	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		b.logger.Error("failed to create storage entry", "error", err)
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		b.logger.Error("failed to save configuration", "error", err)
		return nil, err
	}

	b.logger.Info("configuration saved successfully")

	return &logical.Response{
		Data: map[string]interface{}{
			"message": "Configuration saved successfully",
		},
	}, nil
}

func (b *dualLDAPBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"url":             config.URL,
			"binddn":          config.BindDN,
			"userdn":          config.UserDN,
			"userattr":        config.UserAttr,
			"username":        config.Username,
			"rotation_period": int(config.RotationPeriod.Seconds()),
			"password_length": config.PasswordLength,
		},
	}, nil
}

func (b *dualLDAPBackend) pathRotatePassword(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("no configuration found"), nil
	}

	if err := b.rotatePassword(ctx, req.Storage, config); err != nil {
		return logical.ErrorResponse("failed to rotate password: %s", err.Error()), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"message": "Password rotated successfully",
		},
	}, nil
}

func (b *dualLDAPBackend) pathCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	password, err := b.getCurrentPassword(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("no configuration found"), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"username": config.Username,
			"password": password,
		},
	}, nil
}

// Static role handlers
func (b *dualLDAPBackend) pathStaticRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	defer func() {
		if r := recover(); r != nil {
			b.logger.Error("panic in pathStaticRoleWrite", "panic", r)
		}
	}()

	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}

	b.logger.Debug("pathStaticRoleWrite called", "name", name)

	// Check for dual account mode
	dualAccountMode := data.Get("dual_account_mode").(bool)
	b.logger.Debug("dual_account_mode", "value", dualAccountMode)

	if dualAccountMode {
		b.logger.Debug("processing dual account mode")
		// NEW: Dual account creation
		usernameA, ok := data.GetOk("username_a")
		if !ok || usernameA.(string) == "" {
			return logical.ErrorResponse("username_a is required for dual account mode"), nil
		}

		usernameB, ok := data.GetOk("username_b")
		if !ok || usernameB.(string) == "" {
			return logical.ErrorResponse("username_b is required for dual account mode"), nil
		}

		b.logger.Debug("usernames found", "username_a", usernameA, "username_b", usernameB)

		// Validate that these usernames aren't already in use by another role
		if err := b.validateUsernamesNotInUse(ctx, req.Storage, name, usernameA.(string), usernameB.(string)); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		gracePeriod := data.Get("grace_period").(int)
		if gracePeriod == 0 {
			gracePeriod = 259200 // 3 days default
		}

		rotationPeriod := data.Get("rotation_period").(int)
		if rotationPeriod == 0 {
			rotationPeriod = 1209600 // 14 days default
		}

		passwordLength := data.Get("password_length").(int)
		if passwordLength == 0 {
			passwordLength = defaultPasswordLength
		}

		// Generate initial passwords
		passA, err := generatePassword(passwordLength)
		if err != nil {
			return nil, err
		}
		passB, err := generatePassword(passwordLength)
		if err != nil {
			return nil, err
		}

		// Initialize dual account role
		role := &staticRole{
			DualAccountMode: true,
			AccountA: dualAccountInfo{
				Username:        usernameA.(string),
				CurrentPassword: passA,
				Status:          "active",
			},
			AccountB: dualAccountInfo{
				Username:        usernameB.(string),
				CurrentPassword: passB,
				Status:          "inactive",
			},
			RotationPeriod:   time.Duration(rotationPeriod) * time.Second,
			GracePeriod:      time.Duration(gracePeriod) * time.Second,
			CurrentActive:    "account_a",
			LastRotationTime: time.Now().Unix(),
			RotationState: rotationStateInfo{
				State:          "account_a_active",
				ActiveAccount:  "account_a",
				NextAccount:    "account_b",
				StateStartTime: time.Now().Unix(),
			},
			PasswordLength: passwordLength,
		}

		// Get LDAP config
		config, err := b.getConfig(ctx, req.Storage)
		if err != nil {
			b.logger.Error("failed to get config", "error", err)
			return nil, err
		}
		if config == nil {
			return logical.ErrorResponse("LDAP configuration not found"), nil
		}

		b.logger.Debug("got config", "url", config.URL, "userdn", config.UserDN)

		// Update Account A on LDAP server
		b.logger.Debug("updating account_a", "username", role.AccountA.Username)
		if err := b.updateLDAPPasswordForUser(config, config.URL, role.AccountA.Username, passA); err != nil {
			b.logger.Error("failed to update account_a", "error", err)
			return logical.ErrorResponse("failed to set Account A password: %s", err.Error()), nil
		}

		// Update Account B on LDAP server
		if err := b.updateLDAPPasswordForUser(config, config.URL, role.AccountB.Username, passB); err != nil {
			return logical.ErrorResponse("failed to set Account B password: %s", err.Error()), nil
		}

		// Store role
		entry, err := logical.StorageEntryJSON(staticRolePath+name, role)
		if err != nil {
			return nil, err
		}
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, err
		}

		b.logger.Info("dual account role created", "name", name,
			"account_a", role.AccountA.Username, "account_b", role.AccountB.Username)

		return &logical.Response{
			Data: map[string]interface{}{
				"message": fmt.Sprintf("Dual account role '%s' created successfully", name),
			},
		}, nil
	}

	// EXISTING: Single account creation (backward compatible)
	username, ok := data.GetOk("username")
	if !ok || username.(string) == "" {
		return logical.ErrorResponse("username is required"), nil
	}

	rotationPeriod := data.Get("rotation_period").(int)
	if rotationPeriod == 0 {
		rotationPeriod = 60
	}

	passwordLength := data.Get("password_length").(int)
	if passwordLength == 0 {
		passwordLength = defaultPasswordLength
	}

	role := &staticRole{
		Username:       username.(string),
		RotationPeriod: time.Duration(rotationPeriod) * time.Second,
		PasswordLength: passwordLength,
	}

	entry, err := logical.StorageEntryJSON(staticRolePath+name, role)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.logger.Info("static role created", "name", name, "username", role.Username)

	return &logical.Response{
		Data: map[string]interface{}{
			"message": fmt.Sprintf("Static role '%s' created successfully", name),
		},
	}, nil
}

func (b *dualLDAPBackend) pathStaticRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}

	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	responseData := map[string]interface{}{
		"rotation_period": int(role.RotationPeriod.Seconds()),
		"password_length": role.PasswordLength,
	}

	// Add dual-account specific fields
	if role.DualAccountMode {
		responseData["dual_account_mode"] = true

		// Determine active and standby usernames
		var activeUsername, standbyUsername string
		if role.CurrentActive == "account_a" {
			activeUsername = role.AccountA.Username
			standbyUsername = role.AccountB.Username
		} else {
			activeUsername = role.AccountB.Username
			standbyUsername = role.AccountA.Username
		}

		responseData["active_username"] = activeUsername
		responseData["standby_username"] = standbyUsername
		responseData["grace_period"] = int(role.GracePeriod.Seconds())
		responseData["last_rotation_time"] = role.LastRotationTime

		// Simplify rotation state
		var simpleState string
		switch role.RotationState.State {
		case "account_a_active", "account_b_active":
			simpleState = "active"
		case "grace_period_a_to_b", "grace_period_b_to_a":
			simpleState = "grace_period"
		default:
			simpleState = role.RotationState.State
		}
		responseData["rotation_state"] = simpleState
	} else {
		// Single-account mode
		responseData["dual_account_mode"] = false
		responseData["username"] = role.Username
	}

	return &logical.Response{
		Data: responseData,
	}, nil
}

func (b *dualLDAPBackend) pathStaticRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}

	if err := req.Storage.Delete(ctx, staticRolePath+name); err != nil {
		return nil, err
	}

	// Also delete the stored credentials for this role
	if err := req.Storage.Delete(ctx, staticCredPath+name); err != nil {
		b.logger.Warn("failed to delete credentials for role", "name", name, "error", err)
	}

	b.logger.Info("static role deleted", "name", name)

	return &logical.Response{
		Data: map[string]interface{}{
			"message": fmt.Sprintf("Static role '%s' deleted successfully", name),
		},
	}, nil
}

func (b *dualLDAPBackend) pathStaticCredRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}

	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("static role '%s' not found", name), nil
	}

	// NEW: Dual account credential response
	if role.DualAccountMode {
		var activeAccount, standbyAccount dualAccountInfo
		if role.CurrentActive == "account_a" {
			activeAccount = role.AccountA
			standbyAccount = role.AccountB
		} else {
			activeAccount = role.AccountB
			standbyAccount = role.AccountA
		}

		daysUntilRotation := int(role.RotationPeriod.Hours() / 24)
		if role.RotationState.State == "grace_period_a_to_b" ||
			role.RotationState.State == "grace_period_b_to_a" {
			daysUntilRotation = int(time.Until(time.Unix(role.RotationState.GracePeriodEndTime, 0)).Hours() / 24)
		}

		// Simplify rotation state
		var simpleState string
		switch role.RotationState.State {
		case "account_a_active", "account_b_active":
			simpleState = "active"
		case "grace_period_a_to_b", "grace_period_b_to_a":
			simpleState = "grace_period"
		default:
			simpleState = role.RotationState.State
		}

		responseData := map[string]interface{}{
			"username":               activeAccount.Username,
			"password":               activeAccount.CurrentPassword,
			"rotation_state":         simpleState,
			"days_until_rotation":    daysUntilRotation,
			"last_rotated":           role.LastRotationTime,
			"last_rotated_formatted": time.Unix(role.LastRotationTime, 0).Format(time.RFC3339),
			"metadata": map[string]interface{}{
				"active_account": map[string]interface{}{
					"username":          activeAccount.Username,
					"password":          activeAccount.CurrentPassword,
					"last_rotated":      activeAccount.LastRotated,
					"last_rotated_fmt":  time.Unix(activeAccount.LastRotated, 0).Format(time.RFC3339),
					"previous_password": activeAccount.PreviousPassword,
				},
				"standby_account": map[string]interface{}{
					"username":          standbyAccount.Username,
					"password":          standbyAccount.CurrentPassword,
					"last_rotated":      standbyAccount.LastRotated,
					"last_rotated_fmt":  time.Unix(standbyAccount.LastRotated, 0).Format(time.RFC3339),
					"previous_password": standbyAccount.PreviousPassword,
				},
			},
		}

		return &logical.Response{
			Data: responseData,
		}, nil
	}

	// EXISTING: Single account credential response (backward compatible)
	// Get or generate password for this role
	password, err := b.getRolePassword(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	// If no password exists, rotate to create one
	if password == "" {
		config, err := b.getConfig(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		if config == nil {
			return logical.ErrorResponse("no configuration found"), nil
		}

		if err := b.rotateRolePassword(ctx, req.Storage, config, name, role); err != nil {
			return logical.ErrorResponse("failed to initialize password: %s", err.Error()), nil
		}

		password, err = b.getRolePassword(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"username": role.Username,
			"password": password,
		},
	}, nil
}

func (b *dualLDAPBackend) pathRotateRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}

	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("static role '%s' not found", name), nil
	}

	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("no configuration found"), nil
	}

	// Handle dual-account vs single-account rotation
	if role.DualAccountMode {
		if err := b.rotateDualAccountPassword(ctx, req.Storage, config, name, role); err != nil {
			return logical.ErrorResponse("failed to rotate password: %s", err.Error()), nil
		}
	} else {
		if err := b.rotateRolePassword(ctx, req.Storage, config, name, role); err != nil {
			return logical.ErrorResponse("failed to rotate password: %s", err.Error()), nil
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"message": fmt.Sprintf("Password for role '%s' rotated successfully", name),
		},
	}, nil
}

func (b *dualLDAPBackend) rotatePassword(ctx context.Context, storage logical.Storage, config *ldapConfig) error {
	// Generate new password
	newPassword, err := generatePassword(config.PasswordLength)
	if err != nil {
		return fmt.Errorf("failed to generate password: %w", err)
	}

	b.logger.Info("rotating password on LDAP server", "username", config.Username)

	// Update LDAP server
	if err := b.updateLDAPPassword(config, config.URL, newPassword); err != nil {
		b.logger.Error("failed to update LDAP server", "error", err)
		return fmt.Errorf("failed to update LDAP server: %w", err)
	}
	b.logger.Info("successfully updated LDAP server")

	// Store new password in Vault
	if err := b.storePassword(ctx, storage, newPassword); err != nil {
		b.logger.Error("failed to store new password in Vault", "error", err)
		return err
	}

	b.logger.Info("password rotation completed successfully")
	return nil
}

func (b *dualLDAPBackend) updateLDAPPassword(config *ldapConfig, serverURL string, newPassword string) error {
	// Parse and dial LDAP server
	l, err := ldap.DialURL(serverURL)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", serverURL, err)
	}
	defer l.Close()

	// Bind with admin credentials
	if err := l.Bind(config.BindDN, config.BindPassword); err != nil {
		return fmt.Errorf("failed to bind to %s: %w", serverURL, err)
	}

	// Construct user DN from username and base DN
	userAttr := config.UserAttr
	if userAttr == "" {
		userAttr = defaultUserAttr
	}

	// Search for the user
	searchRequest := ldap.NewSearchRequest(
		config.UserDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(%s=%s)", userAttr, ldap.EscapeFilter(config.Username)),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("failed to search for user: %w", err)
	}

	if len(sr.Entries) == 0 {
		return fmt.Errorf("user %s not found", config.Username)
	}
	if len(sr.Entries) > 1 {
		return fmt.Errorf("multiple users found matching %s", config.Username)
	}

	userDN := sr.Entries[0].DN

	// Use password modify extended operation (RFC 3062)
	passwordModifyRequest := ldap.NewPasswordModifyRequest(userDN, "", newPassword)
	_, err = l.PasswordModify(passwordModifyRequest)
	if err != nil {
		return fmt.Errorf("failed to modify password: %w", err)
	}

	return nil
}

func generatePassword(length int) (string, error) {
	if length <= 0 {
		length = defaultPasswordLength
	}

	// Use base62 for simpler password generation
	password, err := base62.Random(length)
	if err != nil {
		// Fallback to crypto/rand if base62 fails
		return generatePasswordWithCharset(length)
	}
	return password, nil
}

func generatePasswordWithCharset(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	password := make([]byte, length)

	for i := range password {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		password[i] = charset[num.Int64()]
	}

	return string(password), nil
}

func (b *dualLDAPBackend) getConfig(ctx context.Context, storage logical.Storage) (*ldapConfig, error) {
	entry, err := storage.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := &ldapConfig{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}

	return config, nil
}

func (b *dualLDAPBackend) storePassword(ctx context.Context, storage logical.Storage, password string) error {
	entry, err := logical.StorageEntryJSON("current_password", map[string]interface{}{
		"password":   password,
		"rotated_at": time.Now().Unix(),
	})
	if err != nil {
		return err
	}

	return storage.Put(ctx, entry)
}

func (b *dualLDAPBackend) getCurrentPassword(ctx context.Context, storage logical.Storage) (string, error) {
	entry, err := storage.Get(ctx, "current_password")
	if err != nil {
		return "", err
	}
	if entry == nil {
		return "", nil
	}

	var data map[string]interface{}
	if err := entry.DecodeJSON(&data); err != nil {
		return "", err
	}

	if password, ok := data["password"].(string); ok {
		return password, nil
	}

	return "", nil
}

func (b *dualLDAPBackend) getStaticRole(ctx context.Context, storage logical.Storage, name string) (*staticRole, error) {
	entry, err := storage.Get(ctx, staticRolePath+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	role := &staticRole{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}

	return role, nil
}

func (b *dualLDAPBackend) getRolePassword(ctx context.Context, storage logical.Storage, roleName string) (string, error) {
	entry, err := storage.Get(ctx, staticCredPath+roleName)
	if err != nil {
		return "", err
	}
	if entry == nil {
		return "", nil
	}

	var data map[string]interface{}
	if err := entry.DecodeJSON(&data); err != nil {
		return "", err
	}

	if password, ok := data["password"].(string); ok {
		return password, nil
	}

	return "", nil
}

func (b *dualLDAPBackend) storeRolePassword(ctx context.Context, storage logical.Storage, roleName string, password string) error {
	entry, err := logical.StorageEntryJSON(staticCredPath+roleName, map[string]interface{}{
		"password":      password,
		"rotated_at":    time.Now().Unix(),
		"last_rotation": time.Now().Unix(),
	})
	if err != nil {
		return err
	}

	return storage.Put(ctx, entry)
}

func (b *dualLDAPBackend) rotateRolePassword(ctx context.Context, storage logical.Storage, config *ldapConfig, roleName string, role *staticRole) error {
	// Generate new password
	newPassword, err := generatePassword(role.PasswordLength)
	if err != nil {
		return fmt.Errorf("failed to generate password: %w", err)
	}

	b.logger.Info("rotating password for static role", "role", roleName, "username", role.Username)

	// Update LDAP server
	if err := b.updateLDAPPasswordForUser(config, config.URL, role.Username, newPassword); err != nil {
		b.logger.Error("failed to update LDAP server", "role", roleName, "error", err)
		return fmt.Errorf("failed to update LDAP server: %w", err)
	}
	b.logger.Info("successfully updated LDAP server", "role", roleName)

	// Store new password in Vault
	if err := b.storeRolePassword(ctx, storage, roleName, newPassword); err != nil {
		b.logger.Error("failed to store new password in Vault", "role", roleName, "error", err)
		return err
	}

	b.logger.Info("password rotation completed successfully", "role", roleName)
	return nil
}

func (b *dualLDAPBackend) updateLDAPPasswordForUser(config *ldapConfig, serverURL string, username string, newPassword string) error {
	// Parse and dial LDAP server
	l, err := ldap.DialURL(serverURL)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", serverURL, err)
	}
	defer l.Close()

	// Bind with admin credentials
	if err := l.Bind(config.BindDN, config.BindPassword); err != nil {
		return fmt.Errorf("failed to bind to %s: %w", serverURL, err)
	}

	// Construct user DN from username and base DN
	userAttr := config.UserAttr
	if userAttr == "" {
		userAttr = defaultUserAttr
	}

	// Search for the user
	searchRequest := ldap.NewSearchRequest(
		config.UserDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(%s=%s)", userAttr, ldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("failed to search for user: %w", err)
	}

	if len(sr.Entries) == 0 {
		return fmt.Errorf("user %s not found", username)
	}
	if len(sr.Entries) > 1 {
		return fmt.Errorf("multiple users found matching %s", username)
	}

	userDN := sr.Entries[0].DN

	// Use password modify extended operation (RFC 3062)
	passwordModifyRequest := ldap.NewPasswordModifyRequest(userDN, "", newPassword)
	_, err = l.PasswordModify(passwordModifyRequest)
	if err != nil {
		return fmt.Errorf("failed to modify password: %w", err)
	}

	return nil
}

// pathStaticRoleStateRead returns the current rotation state for a dual-account role
func (b *dualLDAPBackend) pathStaticRoleStateRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}

	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("static role '%s' not found", name), nil
	}

	if !role.DualAccountMode {
		return logical.ErrorResponse("role '%s' is not in dual account mode", name), nil
	}

	now := time.Now()
	stateStart := time.Unix(role.RotationState.StateStartTime, 0)
	gracePeriodEnd := time.Unix(role.RotationState.GracePeriodEndTime, 0)

	var elapsed, remaining int64

	switch role.RotationState.State {
	case "account_a_active", "account_b_active":
		elapsed = int64(now.Sub(stateStart).Seconds())
		remaining = int64(role.RotationPeriod.Seconds()) - elapsed
	case "grace_period_a_to_b", "grace_period_b_to_a":
		elapsed = int64(now.Sub(stateStart).Seconds())
		remaining = gracePeriodEnd.Unix() - now.Unix()
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"rotation_state":             role.RotationState.State,
			"current_active_account":     role.CurrentActive,
			"active_since":               stateStart.Format(time.RFC3339),
			"seconds_elapsed_in_state":   elapsed,
			"seconds_remaining_in_state": remaining,
			"grace_period_end":           gracePeriodEnd.Format(time.RFC3339),
			"account_a": map[string]interface{}{
				"username":     role.AccountA.Username,
				"status":       role.AccountA.Status,
				"last_rotated": time.Unix(role.AccountA.LastRotated, 0).Format(time.RFC3339),
			},
			"account_b": map[string]interface{}{
				"username":     role.AccountB.Username,
				"status":       role.AccountB.Status,
				"last_rotated": time.Unix(role.AccountB.LastRotated, 0).Format(time.RFC3339),
			},
		},
	}, nil
}

// shouldTransitionState checks if a dual-account role needs a state transition
func (b *dualLDAPBackend) shouldTransitionState(ctx context.Context, storage logical.Storage, roleName string, role *staticRole) bool {
	if !role.DualAccountMode {
		return false
	}

	now := time.Now()
	stateStart := time.Unix(role.RotationState.StateStartTime, 0)

	switch role.RotationState.State {
	case "account_a_active":
		return now.Sub(stateStart) > role.RotationPeriod
	case "grace_period_a_to_b":
		return now.Unix() > role.RotationState.GracePeriodEndTime
	case "account_b_active":
		return now.Sub(stateStart) > role.RotationPeriod
	case "grace_period_b_to_a":
		return now.Unix() > role.RotationState.GracePeriodEndTime
	}

	return false
}

// transitionRotationState handles state machine transitions for dual-account roles
func (b *dualLDAPBackend) transitionRotationState(ctx context.Context, storage logical.Storage, config *ldapConfig, roleName string, role *staticRole) error {
	oldState := role.RotationState.State
	now := time.Now()

	switch role.RotationState.State {
	case "account_a_active":
		role.RotationState.State = "grace_period_a_to_b"
		role.RotationState.GracePeriodEndTime = now.Add(role.GracePeriod).Unix()
		role.CurrentActive = "account_b"
		role.AccountB.Status = "grace_period"

	case "grace_period_a_to_b":
		role.RotationState.State = "account_b_active"
		role.RotationState.StateStartTime = now.Unix()
		role.AccountB.Status = "active"
		role.AccountA.Status = "inactive"

	case "account_b_active":
		role.RotationState.State = "grace_period_b_to_a"
		role.RotationState.GracePeriodEndTime = now.Add(role.GracePeriod).Unix()
		role.CurrentActive = "account_a"
		role.AccountA.Status = "grace_period"

	case "grace_period_b_to_a":
		role.RotationState.State = "account_a_active"
		role.RotationState.StateStartTime = now.Unix()
		role.AccountA.Status = "active"
		role.AccountB.Status = "inactive"
	}

	b.logger.Info("dual account state transition", "role", roleName, "from", oldState, "to", role.RotationState.State)
	return b.storeDualAccountState(ctx, storage, roleName, role)
}

// storeDualAccountState persists the dual account role state
func (b *dualLDAPBackend) storeDualAccountState(ctx context.Context, storage logical.Storage, roleName string, role *staticRole) error {
	entry, err := logical.StorageEntryJSON(staticRolePath+roleName, role)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// rotateDualAccountPassword handles password rotation for dual-account roles
func (b *dualLDAPBackend) rotateDualAccountPassword(ctx context.Context, storage logical.Storage, config *ldapConfig, roleName string, role *staticRole) error {
	if !role.DualAccountMode {
		return fmt.Errorf("role is not in dual account mode")
	}

	newPassword, err := generatePassword(role.PasswordLength)
	if err != nil {
		return fmt.Errorf("failed to generate password: %w", err)
	}

	var accountToRotate *dualAccountInfo
	var accountUsername string
	var accountName string

	switch role.RotationState.State {
	case "account_a_active":
		accountToRotate = &role.AccountB
		accountUsername = role.AccountB.Username
		accountName = "account_b"
	case "grace_period_a_to_b":
		accountToRotate = &role.AccountB
		accountUsername = role.AccountB.Username
		accountName = "account_b"
	case "account_b_active":
		accountToRotate = &role.AccountA
		accountUsername = role.AccountA.Username
		accountName = "account_a"
	case "grace_period_b_to_a":
		accountToRotate = &role.AccountA
		accountUsername = role.AccountA.Username
		accountName = "account_a"
	default:
		return fmt.Errorf("unknown rotation state: %s", role.RotationState.State)
	}

	b.logger.Info("rotating password for dual account", "role", roleName, "account", accountName, "username", accountUsername)

	if err := b.updateLDAPPasswordForUser(config, config.URL, accountUsername, newPassword); err != nil {
		b.logger.Error("failed to update LDAP server", "role", roleName, "error", err)
		return fmt.Errorf("failed to update %s: %w", accountName, err)
	}
	b.logger.Info("successfully updated LDAP server", "role", roleName)

	accountToRotate.PreviousPassword = accountToRotate.CurrentPassword
	accountToRotate.CurrentPassword = newPassword
	accountToRotate.NextPassword = ""
	accountToRotate.LastRotated = time.Now().Unix()

	if err := b.storeDualAccountState(ctx, storage, roleName, role); err != nil {
		b.logger.Error("failed to store dual account state", "role", roleName, "error", err)
		return err
	}

	return nil
}

// validateUsernamesNotInUse checks if the given LDAP usernames are already used by another role
func (b *dualLDAPBackend) validateUsernamesNotInUse(ctx context.Context, storage logical.Storage, currentRoleName string, usernameA string, usernameB string) error {
	// List all static roles
	roles, err := storage.List(ctx, staticRolePath)
	if err != nil {
		return fmt.Errorf("failed to list roles: %w", err)
	}

	// Check each role for username conflicts
	for _, roleName := range roles {
		// Skip the current role being created/updated
		if roleName == currentRoleName {
			continue
		}

		role, err := b.getStaticRole(ctx, storage, roleName)
		if err != nil {
			b.logger.Warn("failed to get role during validation", "role", roleName, "error", err)
			continue
		}
		if role == nil {
			continue
		}

		// Check dual-account roles
		if role.DualAccountMode {
			if role.AccountA.Username == usernameA {
				return fmt.Errorf("username '%s' is already in use by role '%s' (account_a)", usernameA, roleName)
			}
			if role.AccountA.Username == usernameB {
				return fmt.Errorf("username '%s' is already in use by role '%s' (account_a)", usernameB, roleName)
			}
			if role.AccountB.Username == usernameA {
				return fmt.Errorf("username '%s' is already in use by role '%s' (account_b)", usernameA, roleName)
			}
			if role.AccountB.Username == usernameB {
				return fmt.Errorf("username '%s' is already in use by role '%s' (account_b)", usernameB, roleName)
			}
		} else {
			// Check single-account roles
			if role.Username == usernameA {
				return fmt.Errorf("username '%s' is already in use by single-account role '%s'", usernameA, roleName)
			}
			if role.Username == usernameB {
				return fmt.Errorf("username '%s' is already in use by single-account role '%s'", usernameB, roleName)
			}
		}
	}

	return nil
}
