# ServerPilot Build Automation
# ============================================================================
# Builds cross-compiled binaries, manages releases, and updates the Homebrew
# formula. Inspired by the versionator distribution system.
#
# Usage:
#   make              Build everything for the current version
#   make build-all    Cross-compile all platform binaries
#   make clean        Remove build artifacts
# ============================================================================

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

VERSION      := $(shell grep 'const Version' ../version.go | sed 's/.*"\(.*\)"/\1/')
PREV_VERSION := $(shell ls -1 ../release/ 2>/dev/null | sort -V | tail -1)
BIN_NAME     := sp
MODULE       := $(shell grep '^module' ../go.mod | awk '{print $$2}')

BUILD_DIR    := ../release/$(VERSION)
FORMULA_DIR  := ../homebrew/Formula
FORMULA      := $(FORMULA_DIR)/sp.rb

REPO_URL     := https://github.com/mrthoabby/serverpilot/releases/download

# Build flags
LDFLAGS      := -s -w -X main.Version=$(VERSION)
GOFLAGS      := -trimpath

# Platform matrix
PLATFORMS    := linux-amd64 linux-arm64 darwin-amd64 darwin-arm64

# GNU vs BSD: sed -i and sha256
ifeq ($(shell uname -s),Darwin)
  SEDI     := sed -i ''
  SHA256OF := shasum -a 256
else
  SEDI     := sed -i
  SHA256OF := sha256sum
endif

# ---------------------------------------------------------------------------
# Default target
# ---------------------------------------------------------------------------

.PHONY: all
all: ensure-formula release-dir build-all archive-prev update-formula
	@echo ""
	@echo "============================================"
	@echo "  Build complete: $(BIN_NAME) v$(VERSION)"
	@echo "============================================"
	@echo ""
	@echo "Binaries:"
	@ls -lh $(BUILD_DIR)/
	@echo ""

# ---------------------------------------------------------------------------
# ensure-formula: create Homebrew boilerplate if it does not exist
# ---------------------------------------------------------------------------

.PHONY: ensure-formula
ensure-formula:
	@mkdir -p $(FORMULA_DIR)
	@if [ ! -f $(FORMULA) ]; then \
		echo "Creating boilerplate Homebrew formula..."; \
		echo 'class Sp < Formula'                                          >  $(FORMULA); \
		echo '  desc "Server management dashboard for Docker & Nginx"'     >> $(FORMULA); \
		echo '  homepage "https://github.com/mrthoabby/serverpilot"'    >> $(FORMULA); \
		echo '  version "$(VERSION)"'                                      >> $(FORMULA); \
		echo '  license "MIT"'                                             >> $(FORMULA); \
		echo ''                                                            >> $(FORMULA); \
		echo '  on_macos do'                                               >> $(FORMULA); \
		echo '    if Hardware::CPU.arm?'                                   >> $(FORMULA); \
		echo '      url "$(REPO_URL)/v$(VERSION)/$(BIN_NAME)-darwin-arm64"' >> $(FORMULA); \
		echo '      sha256 "PLACEHOLDER"'                                  >> $(FORMULA); \
		echo '    else'                                                    >> $(FORMULA); \
		echo '      url "$(REPO_URL)/v$(VERSION)/$(BIN_NAME)-darwin-amd64"' >> $(FORMULA); \
		echo '      sha256 "PLACEHOLDER"'                                  >> $(FORMULA); \
		echo '    end'                                                     >> $(FORMULA); \
		echo '  end'                                                       >> $(FORMULA); \
		echo ''                                                            >> $(FORMULA); \
		echo '  on_linux do'                                               >> $(FORMULA); \
		echo '    if Hardware::CPU.arm?'                                   >> $(FORMULA); \
		echo '      url "$(REPO_URL)/v$(VERSION)/$(BIN_NAME)-linux-arm64"'  >> $(FORMULA); \
		echo '      sha256 "PLACEHOLDER"'                                  >> $(FORMULA); \
		echo '    else'                                                    >> $(FORMULA); \
		echo '      url "$(REPO_URL)/v$(VERSION)/$(BIN_NAME)-linux-amd64"'  >> $(FORMULA); \
		echo '      sha256 "PLACEHOLDER"'                                  >> $(FORMULA); \
		echo '    end'                                                     >> $(FORMULA); \
		echo '  end'                                                       >> $(FORMULA); \
		echo ''                                                            >> $(FORMULA); \
		echo '  def install'                                               >> $(FORMULA); \
		echo '    bin.install Dir["$(BIN_NAME)-*"].first => "$(BIN_NAME)"' >> $(FORMULA); \
		echo '  end'                                                       >> $(FORMULA); \
		echo ''                                                            >> $(FORMULA); \
		echo '  test do'                                                   >> $(FORMULA); \
		echo '    system "#{bin}/$(BIN_NAME)", "version"'                  >> $(FORMULA); \
		echo '  end'                                                       >> $(FORMULA); \
		echo 'end'                                                         >> $(FORMULA); \
	fi

# ---------------------------------------------------------------------------
# release-dir: create the versioned release directory
# ---------------------------------------------------------------------------

.PHONY: release-dir
release-dir:
	@mkdir -p $(BUILD_DIR)
	@echo "Release directory ready: $(BUILD_DIR)"

# ---------------------------------------------------------------------------
# build-all: cross-compile for every platform
# ---------------------------------------------------------------------------

.PHONY: build-all
build-all: $(addprefix build-,$(PLATFORMS))

# Pure-make GOOS/GOARCH: avoid $$ARCH ($$A + $(R)...), $$OS, and $$(echo which confuses make.
define BUILD_RULE
.PHONY: build-$(1)
build-$(1):
	@echo "Building $(BIN_NAME)-$(1)..."; \
	cd .. && CGO_ENABLED=0 \
		GOOS=$(word 1,$(subst -, ,$(1))) \
		GOARCH=$(word 2,$(subst -, ,$(1))) \
		go build $(GOFLAGS) -ldflags '$(LDFLAGS)' \
		-o release/$(VERSION)/$(BIN_NAME)-$(1) .
endef

$(foreach platform,$(PLATFORMS),$(eval $(call BUILD_RULE,$(platform))))

# ---------------------------------------------------------------------------
# archive-prev: rename old formula as sp@{OLD_VERSION}.rb
# ---------------------------------------------------------------------------

.PHONY: archive-prev
archive-prev:
	@if [ -n "$(PREV_VERSION)" ] && [ "$(PREV_VERSION)" != "$(VERSION)" ]; then \
		if [ -f $(FORMULA) ]; then \
			ARCHIVE="$(FORMULA_DIR)/sp@$(PREV_VERSION).rb"; \
			if [ ! -f "$$ARCHIVE" ]; then \
				echo "Archiving previous formula as sp@$(PREV_VERSION).rb"; \
				cp $(FORMULA) "$$ARCHIVE"; \
				$(SEDI) 's/class Sp </class SpAT$(PREV_VERSION) </' "$$ARCHIVE"; \
			else \
				echo "Archive sp@$(PREV_VERSION).rb already exists, skipping."; \
			fi; \
		fi; \
	else \
		echo "No previous version to archive (or same version)."; \
	fi

# ---------------------------------------------------------------------------
# update-formula: recalculate SHA256 hashes and patch sp.rb
# ---------------------------------------------------------------------------

.PHONY: update-formula
update-formula:
	@echo "Updating Homebrew formula with SHA256 hashes..."
	@for platform in $(PLATFORMS); do \
		BINARY="$(BUILD_DIR)/$(BIN_NAME)-$$platform"; \
		if [ -f "$$BINARY" ]; then \
			SHA=$$($(SHA256OF) "$$BINARY" | awk '{print $$1}'); \
			echo "  $$platform: $$SHA"; \
		fi; \
	done
	@# Update version
	@$(SEDI) 's/version ".*"/version "$(VERSION)"/' $(FORMULA)
	@# Update URLs and hashes for each platform
	@for platform in $(PLATFORMS); do \
		BINARY="$(BUILD_DIR)/$(BIN_NAME)-$$platform"; \
		if [ -f "$$BINARY" ]; then \
			SHA=$$($(SHA256OF) "$$BINARY" | awk '{print $$1}'); \
			OLD_URL_PATTERN="$(BIN_NAME)-$$platform\""; \
			NEW_URL="$(REPO_URL)/v$(VERSION)/$(BIN_NAME)-$$platform\""; \
			$(SEDI) "s|url \".*$(BIN_NAME)-$$platform\"|url \"$$NEW_URL|" $(FORMULA); \
			$(SEDI) "/$(BIN_NAME)-$$platform/{ n; s/sha256 \".*\"/sha256 \"$$SHA\"/; }" $(FORMULA); \
		fi; \
	done
	@echo "Formula updated: $(FORMULA)"

# ---------------------------------------------------------------------------
# clean: remove build artifacts
# ---------------------------------------------------------------------------

.PHONY: clean
	@echo "Cleaning build artifacts..."
clean:
	rm -rf $(BUILD_DIR)
	rm -f ../$(BIN_NAME)
	rm -rf ../dist/
	@echo "Clean complete."

# ---------------------------------------------------------------------------
# Convenience targets
# ---------------------------------------------------------------------------

.PHONY: version
version:
	@echo $(VERSION)

.PHONY: checksums
checksums:
	@cd $(BUILD_DIR) && sha256sum * 2>/dev/null || shasum -a 256 *

.PHONY: help
help:
	@echo "ServerPilot Build System"
	@echo "========================"
	@echo ""
	@echo "Targets:"
	@echo "  all            Build everything (default)"
	@echo "  ensure-formula Create Homebrew formula boilerplate"
	@echo "  release-dir    Create release/VERSION/ directory"
	@echo "  build-all      Cross-compile for all platforms"
	@echo "  archive-prev   Archive previous version formula"
	@echo "  update-formula Update SHA256 hashes in formula"
	@echo "  clean          Remove build artifacts"
	@echo "  version        Print current version"
	@echo "  checksums      Print SHA256 checksums of binaries"
	@echo "  help           Show this help"
	@echo ""
	@echo "Current version: $(VERSION)"
	@echo "Platforms:       $(PLATFORMS)"
