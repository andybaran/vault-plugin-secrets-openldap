# Makefile for Vault Rotating Service Accounts Plugin

PLUGIN_NAME=rotating-service-accounts
PLUGIN_DIR=.
GO=go
VAULT=vault

# Vault configuration
export VAULT_ADDR=http://127.0.0.1:8282
export VAULT_TOKEN=root

.PHONY: all build clean test dev register enable configure rotate creds fmt vet \
	docker-ldap docker-clean docker-adduser docker-verify docker-setup docker-addappuser \
	docker-add-dual-accounts docker-verify-dual-accounts start-rotating-service-accounts-env \
	create-appuser-role create-dual-account-role read-role-state setup-dual-account-plugin \
	configure-ldap read-role get-role-creds rotate-role delete-role \
	setup teardown reload help

all: build

# Build the plugin
build:
	@echo "Building plugin..."
	$(GO) build -o $(PLUGIN_NAME) main.go
	@echo "Plugin built successfully: $(PLUGIN_NAME)"

# Build for production (static binary)
build-prod:
	@echo "Building production binary..."
	CGO_ENABLED=0 $(GO) build -a -ldflags '-extldflags "-static"' -o $(PLUGIN_NAME) main.go
	@echo "Production binary built: $(PLUGIN_NAME)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(PLUGIN_NAME)
	rm -f go.sum
	@echo "Clean complete"

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GO) mod download
	@echo "Dependencies downloaded"

# Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GO) mod tidy
	@echo "Dependencies tidied"

# Run tests
test:
	@echo "Running tests..."
	$(GO) test -v ./...

# Format code
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...

# Run go vet
vet:
	@echo "Running go vet..."
	$(GO) vet ./...

# Calculate SHA256
sha256: build
	@echo "Calculating SHA256..."
	@shasum -a 256 $(PLUGIN_NAME) | cut -d ' ' -f1

# Start Vault dev server
dev: build
	@echo "Starting Vault dev server on port 8282..."
	@mkdir -p ../vault-plugins
	@cp $(PLUGIN_NAME) ../vault-plugins/
	@echo "Plugin directory: $(shell pwd)/../vault-plugins"
	@echo "Vault will be available at: http://127.0.0.1:8282"
	@echo "Root token: root"
	$(VAULT) server -dev -dev-root-token-id=root -dev-plugin-dir=$(shell pwd)/../vault-plugins -dev-listen-address=127.0.0.1:8282

# Register plugin with Vault
register: build
	@echo "Registering plugin with Vault..."
	@mkdir -p ../vault-plugins
	@cp $(PLUGIN_NAME) ../vault-plugins/
	@SHA256=$$(shasum -a 256 ../vault-plugins/$(PLUGIN_NAME) | cut -d ' ' -f1); \
	$(VAULT) plugin register \
		-sha256="$$SHA256" \
		secret \
		$(PLUGIN_NAME)
	@echo "Plugin registered successfully"

# Enable plugin
enable:
	@echo "Enabling plugin..."
	$(VAULT) secrets enable \
		-path=rotating-service-accounts \
		$(PLUGIN_NAME)
	@echo "Plugin enabled at path: rotating-service-accounts"

# Disable plugin
disable:
	@echo "Disabling plugin..."
	$(VAULT) secrets disable rotating-service-accounts
	@echo "Plugin disabled"

# Configure plugin with Docker LDAP servers
configure-ldap:
	@echo "Configuring plugin for Docker LDAP servers..."
	$(VAULT) write rotating-service-accounts/config \
		url="ldap://localhost:389" \
		binddn="cn=admin,dc=learn,dc=example" \
		bindpass="2LearnVault" \
		userdn="ou=users,dc=learn,dc=example" \
		userattr="cn" \
		username="svcaccount" \
		rotation_period=120 \
		password_length=32
	@echo "Plugin configured for local Docker LDAP servers"

# Read configuration
read-config:
	@echo "Reading configuration..."
	$(VAULT) read rotating-service-accounts/config

# Trigger manual rotation
rotate:
	@echo "Triggering password rotation..."
	$(VAULT) write -f rotating-service-accounts/rotate

# Get current credentials
creds:
	@echo "Retrieving current credentials..."
	$(VAULT) read rotating-service-accounts/creds

# Full setup (register, enable, configure)
setup: register enable configure
	@echo "Setup complete!"

# Full teardown
teardown: disable
	@echo "Teardown complete!"

# Reload plugin (useful during development)
reload: disable register enable
	@echo "Plugin reloaded!"

# Setup test LDAP server with Docker
docker-ldap:
	@echo "Starting OpenLDAP test server..."
	@docker run -d \
		--name vault-ldap-server \
		--env LDAP_ORGANISATION="learn" \
		--env LDAP_DOMAIN="learn.example" \
		--env LDAP_ADMIN_PASSWORD="2LearnVault" \
		-p 389:389 \
		-p 636:636 \
		--rm \
		osixia/openldap:1.4.0 || true
	@echo "Waiting for LDAP server to start..."
	@sleep 10
	@echo "LDAP server started:"
	@echo "  Server: ldap://localhost:389"

# Stop and remove test LDAP server
docker-clean:
	@echo "Stopping and removing test LDAP server..."
	@docker stop vault-ldap-server 2>/dev/null || true
	@docker rm vault-ldap-server 2>/dev/null || true
	@echo "LDAP server removed"

# Add test user to LDAP servers
docker-adduser:
	@echo "Creating LDAP configuration file..."
	@printf '%s\n' \
		'dn: ou=groups,dc=learn,dc=example' \
		'objectClass: organizationalunit' \
		'objectClass: top' \
		'ou: groups' \
		'description: groups of users' \
		'' \
		'dn: ou=users,dc=learn,dc=example' \
		'objectClass: organizationalunit' \
		'objectClass: top' \
		'ou: users' \
		'description: users' \
		'' \
		'dn: cn=dev,ou=groups,dc=learn,dc=example' \
		'objectClass: groupofnames' \
		'objectClass: top' \
		'description: testing group for dev' \
		'cn: dev' \
		'member: cn=svcaccount,ou=users,dc=learn,dc=example' \
		'' \
		'dn: cn=svcaccount,ou=users,dc=learn,dc=example' \
		'objectClass: person' \
		'objectClass: top' \
		'cn: svcaccount' \
		'sn: Service' \
		'userPassword: InitialPassword123' \
		> learn-vault-example.ldif
	@echo "Adding configuration to LDAP server..."
	@ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=learn,dc=example" -w 2LearnVault -f learn-vault-example.ldif
	@echo "Test user 'svcaccount' added to LDAP server"
	@rm -f learn-vault-example.ldif

# Verify LDAP server is running and user exists
docker-verify:
	@echo "Verifying LDAP server..."
	@ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=learn,dc=example" -w 2LearnVault -b "cn=svcaccount,ou=users,dc=learn,dc=example"

# Full LDAP setup (start servers and add users)
docker-setup: docker-ldap docker-adduser
	@echo ""
	@echo "LDAP test environment ready!"
	@echo "Use 'make docker-verify' to verify the setup"
	@echo "Use 'make configure-ldap' to configure the Vault plugin"

# Add appuser to LDAP server
docker-addappuser:
	@echo "Creating appuser in LDAP server..."
	@printf '%s\n' \
		'dn: cn=appuser,ou=users,dc=learn,dc=example' \
		'objectClass: person' \
		'objectClass: top' \
		'cn: appuser' \
		'sn: Application' \
		'userPassword: TempPassword123' \
		> appuser.ldif
	@ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=learn,dc=example" -w 2LearnVault -f appuser.ldif 2>/dev/null || echo "  (User already exists)"
	@rm -f appuser.ldif
	@echo "✅ appuser added to LDAP server"

# Add dual accounts (appuser_a and appuser_b) to LDAP server
docker-add-dual-accounts:
	@echo "Creating dual accounts (appuser_a and appuser_b) on LDAP server..."
	@printf '%s\n' \
		'dn: cn=appuser_a,ou=users,dc=learn,dc=example' \
		'objectClass: person' \
		'objectClass: top' \
		'cn: appuser_a' \
		'sn: Application' \
		'userPassword: TempPasswordA123' \
		> appuser_a.ldif
	@printf '%s\n' \
		'dn: cn=appuser_b,ou=users,dc=learn,dc=example' \
		'objectClass: person' \
		'objectClass: top' \
		'cn: appuser_b' \
		'sn: Application' \
		'userPassword: TempPasswordB123' \
		> appuser_b.ldif
	@echo "Adding appuser_a..."
	@ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=learn,dc=example" -w 2LearnVault -f appuser_a.ldif 2>/dev/null || echo "  (appuser_a already exists)"
	@echo "Adding appuser_b..."
	@ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=learn,dc=example" -w 2LearnVault -f appuser_b.ldif 2>/dev/null || echo "  (appuser_b already exists)"
	@rm -f appuser_a.ldif appuser_b.ldif
	@echo "✅ Dual accounts (appuser_a and appuser_b) added to LDAP server"

# Verify dual accounts exist on LDAP server
docker-verify-dual-accounts:
	@echo "Verifying dual accounts on LDAP server..."
	@echo ""
	@echo "Checking appuser_a..."
	@ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=learn,dc=example" -w 2LearnVault -b "cn=appuser_a,ou=users,dc=learn,dc=example" cn 2>/dev/null | grep -q "cn: appuser_a" && echo "  ✅ appuser_a found" || echo "  ❌ appuser_a NOT found"
	@echo ""
	@echo "Checking appuser_b..."
	@ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=learn,dc=example" -w 2LearnVault -b "cn=appuser_b,ou=users,dc=learn,dc=example" cn 2>/dev/null | grep -q "cn: appuser_b" && echo "  ✅ appuser_b found" || echo "  ❌ appuser_b NOT found"
	@echo ""
	@echo "✅ Verification complete"

# Start complete dual LDAP environment (Docker + LDAP servers + dual accounts)
start-rotating-service-accounts-env:
	@echo "🚀 Starting Dual LDAP Environment..."
	@echo ""
	@echo "Step 1: Checking Docker daemon..."
	@docker info >/dev/null 2>&1 || (echo "❌ Docker is not running. Please start Docker Desktop." && exit 1)
	@echo "✅ Docker is running"
	@echo ""
	@echo "Step 2: Starting LDAP servers..."
	@$(MAKE) docker-ldap
	@echo ""
	@echo "Step 3: Creating dual accounts (appuser_a and appuser_b)..."
	@$(MAKE) docker-add-dual-accounts
	@echo ""
	@echo "Step 4: Verifying setup..."
	@$(MAKE) docker-verify-dual-accounts
	@echo ""
	@echo "✅ Dual LDAP environment is ready!"
	@echo ""
	@echo "📋 Next steps:"
	@echo "  1. In another terminal, start Vault: make dev (port 8282)"
	@echo "  2. Register the plugin: make register"
	@echo "  3. Enable the plugin: make enable"
	@echo "  4. Configure for dual accounts: make configure-ldap"
	@echo "  5. Create a dual-account role: make create-dual-account-role ROLE=myapp"
	@echo ""
	@echo "💡 Quick start: make setup-dual-account-plugin (after 'make dev' in another terminal)"
	@echo ""
	@echo "ℹ️  Vault will run on http://127.0.0.1:8282 with root token: root"

# Create a static role for appuser (single-account mode)
create-appuser-role:
	@echo "Creating appuser in LDAP server if needed..."
	@printf '%s\n' \
		'dn: cn=appuser,ou=users,dc=learn,dc=example' \
		'objectClass: person' \
		'objectClass: top' \
		'cn: appuser' \
		'sn: Application' \
		'userPassword: TempPassword123' \
		> appuser.ldif
	@ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=learn,dc=example" -w 2LearnVault -f appuser.ldif 2>/dev/null || echo "  (User already exists)"
	@rm -f appuser.ldif
	@echo "Creating static role for appuser in Vault..."
	$(VAULT) write rotating-service-accounts/static-role/appuser \
		username="appuser" \
		rotation_period=60 \
		password_length=32
	@echo "Static role 'appuser' created"
	@echo "Rotating password..."
	$(VAULT) write -f rotating-service-accounts/rotate-role/appuser
	@echo "Password rotated!"

# Create a dual-account static role
create-dual-account-role:
	@echo "Creating dual-account role '$(ROLE)' in Vault..."
	@if [ -z "$(ROLE)" ]; then \
		echo "❌ Error: ROLE parameter is required"; \
		echo "Usage: make create-dual-account-role ROLE=myapp"; \
		exit 1; \
	fi
	@echo "Ensuring dual accounts exist in LDAP..."
	@$(MAKE) docker-add-dual-accounts
	@echo ""
	@echo "Creating Vault role with dual-account mode..."
	$(VAULT) write rotating-service-accounts/static-role/$(ROLE) \
		username_a="appuser_a" \
		username_b="appuser_b" \
		rotation_period=120 \
		grace_period=30 \
		password_length=32 \
		dual_account_mode=true
	@echo "✅ Dual-account role '$(ROLE)' created successfully"
	@echo ""
	@echo "📋 Next steps:"
	@echo "  - Read credentials: make get-role-creds ROLE=$(ROLE)"
	@echo "  - Check state: make read-role-state ROLE=$(ROLE)"
	@echo "  - Rotate password: make rotate-role ROLE=$(ROLE)"

# Read rotation state for a role
read-role-state:
	@echo "Reading rotation state for role '$(ROLE)'..."
	@if [ -z "$(ROLE)" ]; then \
		echo "❌ Error: ROLE parameter is required"; \
		echo "Usage: make read-role-state ROLE=myapp"; \
		exit 1; \
	fi
	$(VAULT) read rotating-service-accounts/static-role/$(ROLE)/state

# Complete setup for dual-account plugin (run after 'make dev' in another terminal)
setup-dual-account-plugin:
	@echo "🚀 Setting up Dual-Account Plugin..."
	@echo ""
	@echo "Step 1: Registering plugin..."
	@$(MAKE) register
	@echo ""
	@echo "Step 2: Enabling plugin..."
	@$(MAKE) enable
	@echo ""
	@echo "Step 3: Configuring plugin..."
	@$(MAKE) configure-ldap
	@echo ""
	@echo "✅ Plugin setup complete!"
	@echo ""
	@echo "📋 Create a dual-account role with:"
	@echo "  make create-dual-account-role ROLE=myapp"

# Read static role configuration
read-role:
	@echo "Reading static role..."
	$(VAULT) read rotating-service-accounts/static-role/$(ROLE)

# Get credentials for a static role
get-role-creds:
	@echo "Getting credentials for static role..."
	$(VAULT) read rotating-service-accounts/static-cred/$(ROLE)

# Rotate password for a static role
rotate-role:
	@echo "Rotating password for static role..."
	$(VAULT) write -f rotating-service-accounts/rotate-role/$(ROLE)

# Delete a static role
delete-role:
	@echo "Deleting static role..."
	$(VAULT) delete rotating-service-accounts/static-role/$(ROLE)

# Help
help:
	@echo "Available targets:"
	@echo "  build          - Build the plugin"
	@echo "  build-prod     - Build production binary (static)"
	@echo "  clean          - Remove build artifacts"
	@echo "  deps           - Download dependencies"
	@echo "  tidy           - Tidy dependencies"
	@echo "  test           - Run tests"
	@echo "  fmt            - Format code"
	@echo "  vet            - Run go vet"
	@echo "  sha256         - Calculate plugin SHA256"
	@echo "  dev            - Start Vault dev server"
	@echo "  register       - Register plugin with Vault"
	@echo "  enable         - Enable plugin"
	@echo "  disable        - Disable plugin"
	@echo "  configure      - Configure plugin (edit Makefile for your settings)"
	@echo "  read-config    - Read plugin configuration"
	@echo "  rotate         - Trigger manual password rotation"
	@echo "  creds          - Get current credentials"
	@echo "  setup          - Full setup (register, enable, configure)"
	@echo "  teardown       - Full teardown (disable)"
	@echo "  reload         - Reload plugin (disable, register, enable)"
	@echo ""
	@echo "Docker LDAP Test Environment:"
	@echo "  docker-ldap                - Start OpenLDAP test server"
	@echo "  docker-clean               - Stop and remove LDAP server"
	@echo "  docker-adduser             - Add single test user to LDAP server"
	@echo "  docker-add-dual-accounts   - Add dual accounts (appuser_a & appuser_b)"
	@echo "  docker-verify              - Verify LDAP server and test user"
	@echo "  docker-verify-dual-accounts - Verify dual accounts exist"
	@echo "  docker-setup               - Complete setup (docker-ldap + docker-adduser)"
	@echo "  start-rotating-service-accounts-env        - 🚀 Complete dual LDAP environment setup"
	@echo "  configure-ldap             - Configure plugin for Docker LDAP server"
	@echo ""
	@echo "Static Role Management (Single-Account):"
	@echo "  create-appuser-role        - Create static role for appuser"
	@echo "  read-role ROLE=name        - Read static role configuration"
	@echo "  get-role-creds ROLE=name   - Get credentials for a role"
	@echo "  rotate-role ROLE=name      - Rotate password for a role"
	@echo "  delete-role ROLE=name      - Delete a static role"
	@echo ""
	@echo "Dual-Account Role Management:"
	@echo "  create-dual-account-role ROLE=name - Create dual-account static role"
	@echo "  read-role-state ROLE=name          - Read rotation state for dual-account role"
	@echo "  setup-dual-account-plugin          - Complete plugin setup for dual accounts"
	@echo ""
	@echo "Quick Start - Single Account:"
	@echo "  1. make docker-setup         # Start LDAP server and add test user"
	@echo "  2. make dev                  # Start Vault dev server (in another terminal)"
	@echo "  3. make register             # Register the plugin"
	@echo "  4. make enable               # Enable the plugin"
	@echo "  5. make configure-ldap       # Configure for local LDAP"
	@echo "  6. make create-dual-account-role ROLE=myapp  # Create dual-account role"
	@echo "  7. make get-role-creds ROLE=myapp  # Get credentials"
	@echo "  8. make rotate-role ROLE=myapp     # Rotate the password"
	@echo ""
	@echo "Quick Start - Dual Account:"
	@echo "  1. make start-rotating-service-accounts-env           # 🚀 Start complete dual LDAP environment"
	@echo "  2. make dev                           # Start Vault (in another terminal)"
	@echo "  3. make setup-dual-account-plugin     # Setup plugin"
	@echo "  4. make create-dual-account-role ROLE=myapp  # Create dual-account role"
	@echo "  5. make get-role-creds ROLE=myapp     # Get credentials"
	@echo "  6. make read-role-state ROLE=myapp    # Check rotation state"
