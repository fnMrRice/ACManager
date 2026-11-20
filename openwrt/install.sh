#!/bin/sh
# Install the unpacked source bundle. Existing access and AP settings survive.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root'; exit 1; }
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ "$ROOT" = /opt/tplink-ac-lab ] || { echo 'Extract to /opt/tplink-ac-lab first'; exit 1; }
python3 -c 'import ctypes, http.server, http.cookies, hashlib, hmac, json, subprocess, uuid'
umask 077
mkdir -p "$ROOT/data"
chmod 700 "$ROOT/data"
if [ ! -f /etc/config/tplink_ac ]; then
    cp "$ROOT/openwrt/tplink_ac.config" /etc/config/tplink_ac
fi
chmod 600 /etc/config/tplink_ac
cp "$ROOT/openwrt/tplink-ac-lab.init" /etc/init.d/tplink-ac-lab
chmod 755 /etc/init.d/tplink-ac-lab
mkdir -p /www/luci-static/resources/view/tplink_ac /usr/share/luci/menu.d /usr/share/rpcd/acl.d
chmod 755 /www/luci-static/resources/view/tplink_ac
cp "$ROOT/openwrt/luci/config.js" /www/luci-static/resources/view/tplink_ac/config.js
cp "$ROOT/openwrt/luci/menu.json" /usr/share/luci/menu.d/luci-app-tplink-ac.json
cp "$ROOT/openwrt/luci/acl.json" /usr/share/rpcd/acl.d/luci-app-tplink-ac.json
chmod 644 /www/luci-static/resources/view/tplink_ac/config.js /usr/share/luci/menu.d/luci-app-tplink-ac.json /usr/share/rpcd/acl.d/luci-app-tplink-ac.json
/etc/init.d/rpcd reload
/etc/init.d/tplink-ac-lab restart
echo 'Installed. Open LuCI > Network > TP-LINK AC.'
