// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-ldap/ldif"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/vault-plugin-secrets-openldap/client"
	"github.com/hashicorp/vault/sdk/helper/ldaputil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestManualRotateRoot(t *testing.T) {
	t.Run("happy path rotate root", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		originalBindPass := "pa$$w0rd"

		data := map[string]interface{}{
			"binddn":      "tester",
			"bindpass":    originalBindPass,
			"url":         "ldap://138.91.247.105",
			"certificate": validCertificate,
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      rotateRootPath,
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		config, err := readConfig(context.Background(), storage)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if config.LDAP.LastBindPassword != originalBindPass {
			t.Fatalf("expected last_bind_password %q, got %q", originalBindPass,
				config.LDAP.LastBindPassword)
		}
		if config.LDAP.LastBindPasswordRotation.IsZero() {
			t.Fatal("expected last_bind_password_rotation to not be the zero time instant")
		}
	})

	t.Run("rotate root that doesn't exist", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      rotateRootPath,
			Storage:   storage,
			Data:      nil,
		}

		_, err := b.HandleRequest(context.Background(), req)
		if err == nil {
			t.Fatal("should have got error, didn't")
		}
	})
}

func TestManualRotateRole(t *testing.T) {
	t.Run("happy path rotate role", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		roleName := "hashicorp"
		configureOpenLDAPMount(t, b, storage)
		createRole(t, b, storage, roleName)

		resp := readStaticCred(t, b, storage, roleName)

		if resp.Data["password"] == "" {
			t.Fatal("expected password to be set, it wasn't")
		}
		oldPassword := resp.Data["password"]

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      rotateRolePath + roleName,
			Storage:   storage,
			Data:      nil,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		resp = readStaticCred(t, b, storage, roleName)

		if resp.Data["password"] == "" {
			t.Fatal("expected password to be set after rotate, it wasn't")
		}

		if oldPassword == resp.Data["password"] {
			t.Fatal("expected passwords to be different after rotation, they weren't")
		}
	})

	t.Run("happy path rotate role with hierarchical path", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		configureOpenLDAPMount(t, b, storage)

		roles := []string{"org/secure", "org/platform/dev", "org/platform/support"}

		// create all the roles
		for _, role := range roles {
			data := getTestStaticRoleConfig(role)
			createStaticRoleWithData(t, b, storage, role, data)
		}

		passwords := make([]string, 0)
		// rotate all the creds
		for _, role := range roles {
			resp := readStaticCred(t, b, storage, role)

			if resp.Data["password"] == "" {
				t.Fatal("expected password to be set, it wasn't")
			}
			oldPassword := resp.Data["password"]

			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      rotateRolePath + role,
				Storage:   storage,
				Data:      nil,
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}

			resp = readStaticCred(t, b, storage, role)

			newPassword := resp.Data["password"]
			if newPassword == "" {
				t.Fatal("expected password to be set after rotate, it wasn't")
			}

			if oldPassword == newPassword {
				t.Fatal("expected passwords to be different after rotation, they weren't")
			}
			passwords = append(passwords, newPassword.(string))
		}

		// extra pendantic check that the hierarchical paths don't return the same data
		if len(passwords) != len(strutil.RemoveDuplicates(passwords, false)) {
			t.Fatal("expected unique static-role paths to return unique passwords")
		}
	})

	t.Run("rotate role that doesn't exist", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      rotateRolePath + "hashicorp",
			Storage:   storage,
			Data:      nil,
		}

		resp, _ := b.HandleRequest(context.Background(), req)
		if resp == nil || !resp.IsError() {
			t.Fatal("expected error")
		}
	})
}

type failingRollbackClient struct {
	count    int
	maxCount int
	password string
}

func (f *failingRollbackClient) UpdateDNPassword(conf *client.Config, dn string, newPassword string) error {
	f.count += 1
	if f.count >= f.maxCount {
		f.password = newPassword
		return nil
	}
	return fmt.Errorf("some error")
}

func (f *failingRollbackClient) UpdateUserPassword(conf *client.Config, user, newPassword string) error {
	panic("nope")
}

func (f *failingRollbackClient) Execute(conf *client.Config, entries []*ldif.Entry, continueOnError bool) error {
	panic("nope")
}

var _ ldapClient = (*failingRollbackClient)(nil)

type retryableClient struct {
	attempts      int
	succeedAfter  int
	lastPassword  string
	passwords     []string
}

func (r *retryableClient) UpdateDNPassword(conf *client.Config, dn string, newPassword string) error {
	r.attempts++
	r.passwords = append(r.passwords, newPassword)
	r.lastPassword = newPassword
	
	if r.attempts <= r.succeedAfter {
		return fmt.Errorf("password complexity requirements not met")
	}
	return nil
}

func (r *retryableClient) UpdateUserPassword(conf *client.Config, user, newPassword string) error {
	panic("not implemented")
}

func (r *retryableClient) Execute(conf *client.Config, entries []*ldif.Entry, continueOnError bool) error {
	panic("not implemented")
}

var _ ldapClient = (*retryableClient)(nil)

func TestRootRotationRetry(t *testing.T) {
	t.Run("succeeds on first attempt without retry", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		rclient := &retryableClient{succeedAfter: 0}
		b.client = rclient

		configureOpenLDAPMountWithRetry(t, b, storage, 5, 1, 10)

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      rotateRootPath,
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		assert.Equal(t, 1, rclient.attempts, "expected 1 attempt when rotation succeeds immediately")
		assert.Equal(t, 1, len(rclient.passwords), "expected 1 password generated")
	})

	t.Run("succeeds after retries with new passwords", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		rclient := &retryableClient{succeedAfter: 2}
		b.client = rclient

		configureOpenLDAPMountWithRetry(t, b, storage, 5, 1, 10)

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      rotateRootPath,
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		assert.Equal(t, 3, rclient.attempts, "expected 3 attempts (2 failures + 1 success)")
		assert.Equal(t, 3, len(rclient.passwords), "expected 3 unique passwords generated")

		// Verify each password is unique (new password generated on each retry)
		uniquePasswords := make(map[string]bool)
		for _, pwd := range rclient.passwords {
			uniquePasswords[pwd] = true
		}
		assert.Equal(t, 3, len(uniquePasswords), "expected each retry to generate a new password")

		// Verify the config was updated with the successful password
		config, err := readConfig(context.Background(), storage)
		assert.Nil(t, err)
		assert.Equal(t, rclient.lastPassword, config.LDAP.BindPassword, "expected config to have the successful password")
	})

	t.Run("fails after exhausting max retries", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		rclient := &retryableClient{succeedAfter: 10}
		b.client = rclient

		configureOpenLDAPMountWithRetry(t, b, storage, 3, 1, 10)

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      rotateRootPath,
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err == nil {
			t.Fatal("expected error after exhausting retries")
		}
		_ = resp // resp might be nil, not checking it

		assert.Equal(t, 3, rclient.attempts, "expected exactly max_retries attempts")
		assert.Contains(t, err.Error(), "failed after 3 attempts", "error should indicate retry exhaustion")
	})

	t.Run("uses default retry config when not specified", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		rclient := &retryableClient{succeedAfter: 3}
		b.client = rclient

		// Configure without retry settings (should use defaults)
		data := map[string]interface{}{
			"binddn":   "tester",
			"bindpass": "pa$$w0rd",
			"url":      "ldap://138.91.247.105",
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      rotateRootPath,
			Storage:   storage,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		// Default max_retries is 5, so 4 attempts should succeed
		assert.Equal(t, 4, rclient.attempts, "expected to use default max_retries of 5")
	})
}

func TestCalculateExponentialBackoff(t *testing.T) {
	testCases := []struct {
		name      string
		attempt   int
		minDelay  time.Duration
		maxDelay  time.Duration
		expected  time.Duration
	}{
		{"first attempt", 1, 5 * time.Second, 60 * time.Second, 5 * time.Second},
		{"second attempt", 2, 5 * time.Second, 60 * time.Second, 10 * time.Second},
		{"third attempt", 3, 5 * time.Second, 60 * time.Second, 20 * time.Second},
		{"fourth attempt", 4, 5 * time.Second, 60 * time.Second, 40 * time.Second},
		{"capped at max", 5, 5 * time.Second, 60 * time.Second, 60 * time.Second},
		{"exceeds max", 10, 5 * time.Second, 60 * time.Second, 60 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := calculateExponentialBackoff(tc.attempt, tc.minDelay, tc.maxDelay)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func configureOpenLDAPMountWithRetry(t *testing.T, b *backend, storage logical.Storage, maxRetries, minRetryDelay, maxRetryDelay int) {
	data := map[string]interface{}{
		"binddn":                         "tester",
		"bindpass":                       "pa$$w0rd",
		"url":                            "ldap://138.91.247.105",
		"root_rotation_max_retries":      maxRetries,
		"root_rotation_min_retry_delay":  minRetryDelay,
		"root_rotation_max_retry_delay":  maxRetryDelay,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func TestRollbackPassword(t *testing.T) {
	oldRollbackAttempts, oldMinRollbackDuration, oldMaxRollbackDuration := rollbackAttempts, minRollbackDuration, maxRollbackDuration
	t.Cleanup(func() {
		rollbackAttempts = oldRollbackAttempts
		minRollbackDuration = oldMinRollbackDuration
		maxRollbackDuration = oldMaxRollbackDuration
	})
	rollbackAttempts = 5
	minRollbackDuration = 1 * time.Millisecond
	maxRollbackDuration = 10 * time.Millisecond
	oldPassword := "old"
	newPassword := "new"

	testCases := []struct {
		name                  string
		cancelContext         bool
		rollbackSucceedsAfter int
		expectedRollbackCalls int
		expectedPassword      string
		expectErr             bool
	}{
		{"works if client always succeeds", false, 0, 1, oldPassword, false},
		{"work if client eventually succeeds", false, 3, 3, oldPassword, false},
		{"fails if the client errors too many times", false, 20, 5, newPassword, true},
		{"fails if context is canceled", true, 0, 0, newPassword, true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			if testCase.cancelContext {
				canceledCtx, cancelFunc := context.WithCancel(ctx)
				cancelFunc()
				ctx = canceledCtx
			}
			fclient := &failingRollbackClient{}
			b := &backend{
				client: fclient,
			}
			cfg := &config{
				LDAP: &client.Config{
					ConfigEntry: &ldaputil.ConfigEntry{},
				},
			}
			fclient.maxCount = testCase.rollbackSucceedsAfter
			fclient.password = newPassword
			err := b.rollbackPassword(ctx, cfg, oldPassword)
			if testCase.expectErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, testCase.expectedPassword, fclient.password)
			assert.Equal(t, testCase.expectedRollbackCalls, fclient.count)
		})
	}
}
