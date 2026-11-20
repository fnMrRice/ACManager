include $(TOPDIR)/rules.mk

PKG_NAME:=tplink-ac
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
SOURCE_ROOT:=$(if $(wildcard $(CURDIR)/src/tplink_ac),$(CURDIR),$(CURDIR)/../..)

include $(INCLUDE_DIR)/package.mk

define Package/tplink-ac-core
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Experimental TP-LINK CAPWAP controller
  DEPENDS:=+python3-light +python3-ctypes +python3-email +python3-logging +python3-urllib +python3-uuid +python3-openssl +python3-codecs +libopenssl +libgnutls
  PKGARCH:=all
endef

define Package/tplink-ac-webui
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Extracted AC web UI and local API bridge
  PKGARCH:=all
endef

define Package/luci-app-tplink-ac
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=TP-LINK AC access settings
  DEPENDS:=+luci-base +tplink-ac-core +tplink-ac-webui
  PKGARCH:=all
endef

define Package/tplink-ac-core/conffiles
/etc/config/tplink_ac
/opt/tplink-ac-lab/data/settings.json
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) $(SOURCE_ROOT)/src $(SOURCE_ROOT)/web $(SOURCE_ROOT)/openwrt $(PKG_BUILD_DIR)/
	find $(PKG_BUILD_DIR) -type d -name __pycache__ -prune -exec rm -rf {} +
endef

define Build/Compile
endef

define Package/tplink-ac-core/install
	$(INSTALL_DIR) $(1)/opt/tplink-ac-lab/src/tplink_ac $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/tplink_ac/*.py $(1)/opt/tplink-ac-lab/src/tplink_ac/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/tplink-ac-lab.init $(1)/etc/init.d/tplink-ac-lab
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/openwrt/tplink_ac.config $(1)/etc/config/tplink_ac
	chmod 600 $(1)/etc/config/tplink_ac
endef

define Package/tplink-ac-webui/install
	$(INSTALL_DIR) $(1)/opt/tplink-ac-lab/web
	$(CP) $(PKG_BUILD_DIR)/web/. $(1)/opt/tplink-ac-lab/web/
endef

define Package/luci-app-tplink-ac/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/tplink_ac $(1)/usr/share/luci/menu.d $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/openwrt/luci/config.js $(1)/www/luci-static/resources/view/tplink_ac/config.js
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/openwrt/luci/menu.json $(1)/usr/share/luci/menu.d/luci-app-tplink-ac.json
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/openwrt/luci/acl.json $(1)/usr/share/rpcd/acl.d/luci-app-tplink-ac.json
endef

$(eval $(call BuildPackage,tplink-ac-core))
$(eval $(call BuildPackage,tplink-ac-webui))
$(eval $(call BuildPackage,luci-app-tplink-ac))
