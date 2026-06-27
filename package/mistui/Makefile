# OpenWRT package for MistUI.
#
# Like its larger sibling, this deliberately bypasses golang-package.mk: the
# daemon is a CGO-free static binary cross-compiled by CI (or scripts/
# dev-deploy.sh), so the SDK step is pure packaging. Point MISTUI_BIN at the
# prebuilt mistd for the target arch when running `make package/mistui/compile`.

include $(TOPDIR)/rules.mk

PKG_NAME:=mistui
PKG_VERSION:=0.0.1
PKG_RELEASE:=1
PKG_MAINTAINER:=framefilter
PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/mistui
  SECTION:=net
  CATEGORY:=Network
  TITLE:=MistUI — lightweight, private travel-router UI
  URL:=https://github.com/framefilter/mistui
  DEPENDS:=+nginx-ssl +wireguard-tools +nftables +ca-bundle
endef

define Package/mistui/description
  A small, user-friendly web UI for travel routers: WireGuard control,
  passwordless login, and MAC-address privacy. One static binary; runs on
  hardware too small for the heavier stacks.
endef

# The binary is prebuilt; nothing to compile in the SDK.
define Build/Compile
endef

define Package/mistui/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(MISTUI_BIN)/mistd $(1)/usr/bin/mistd
	$(CP) ./files/* $(1)/
endef

$(eval $(call BuildPackage,mistui))
