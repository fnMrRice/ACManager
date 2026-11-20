# ACManager

ACManager 是一个用于集中管理 TP-LINK AP 的无线控制器，提供浏览器管理界面、Python 后端、Windows 启动器和 OpenWrt / LuCI 集成。

## 主要功能

- **AP 管理**：设备发现、接管策略、名称与备注、分组管理、LED 控制、重启与恢复出厂设置。
- **无线服务**：SSID、安全设置、VLAN、隐藏 SSID、客户端隔离，以及无线服务与 AP 射频的绑定。
- **射频设置**：射频开关、信道、发射功率、频谱导航和 EDCA 规则。
- **终端管理**：在线终端信息、流量统计、终端断开、黑名单、按终端数量进行负载均衡和列表导出。
- **运行监控**：AP 状态、无线服务状态、操作结果、事件日志和诊断摘要。
- **配置保存**：连接设置、无线服务、AP 分组及策略保存在本地数据目录。

具体配置项取决于 AP 提供的能力与上报信息；配置下发结果可在页面中查看。数据通道用于本地转发模式下的保活，不提供集中转发。

## Windows 快速启动

安装 Python 3.9 或更新版本，并确保可以在终端运行 `python`。在项目根目录执行：

```powershell
.\run-windows.cmd
```

也可以直接运行启动器：

```powershell
python windows/main.py
```

启动器会自动打开 [管理页面](http://127.0.0.1:8765/)。Windows 启动器的网页服务仅监听本机地址，无需登录。

可选参数：

| 参数 | 说明 | 默认值 |
| --- | --- | --- |
| `--port` | 网页服务端口 | `8765` |
| `--headless` | 不自动打开浏览器 | 自动打开浏览器 |
| `--data-dir` | 数据保存目录 | 项目根目录下的 `data` |

例如：

```powershell
python windows/main.py --port 9000 --headless --data-dir ./data
```

按 `Ctrl+C` 可结束终端中的服务进程。

## 连接 AP

启动 Windows 网页服务后，需要单独配置并启动 AP 通信服务。

1. 打开 [连接设置页面](http://127.0.0.1:8765/setup)。如修改过网页端口，请使用对应端口。
2. 将“本机 AC IPv4”填写为与 AP 通信的本机网卡地址，并填写允许管理的 AP IP。
3. 根据网络配置选择监听地址，确保本机与 AP 之间的 UDP `5246`、`5247` 端口可达。
4. 使用 DTLS 时，填写证书、私钥和信任的 AP CA 的 PEM 文件路径，确保证书符合设备的信任配置。
5. 启用主动管理，保存设置并点击“启动”。仅需观察设备时，可保持主动管理关闭。
6. 返回管理页面，查看 AP 状态并配置无线服务、射频与分组。

修改连接设置前，先在连接设置页面停止 AP 通信服务；保存后重新启动。

默认连接参数：

| 配置项 | 默认值 |
| --- | --- |
| AC IPv4 | `192.168.1.2`，使用前需改为本机实际地址 |
| UDP 监听地址 | `0.0.0.0` |
| CAPWAP 控制端口 | `5246/UDP` |
| CAPWAP 数据端口 | `5247/UDP` |
| 主动管理 | 关闭 |
| DTLS / AP 证书校验 | 开启 |
| DTLS 后端 | 自动选择：Windows 使用 OpenSSL，Linux 使用 GnuTLS |

Windows 的 DTLS 后端需要 OpenSSL 3.2 或更新版本的 `libssl-3.dll` 和 `libcrypto-3.dll`。源码运行时，程序从 Python 安装目录的 `DLLs` 目录加载这两个文件；Linux 默认加载 `libgnutls.so.30`。

如果需要通过页面生成本地证书，先安装可选依赖：

```powershell
python -m pip install cryptography
```

## OpenWrt 部署

项目提供源码安装包和 OpenWrt SDK 打包入口。LuCI 中的“网络 → TP-LINK AC”用于设置网页账号、密码和端口。

在项目根目录生成安装包：

```powershell
python tools/bundle_openwrt.py
```

生成文件：

- `build/tplink-ac-openwrt.tar.gz`：用于直接部署的源码包。
- `build/tplink-ac-sdk-source.tar.gz`：包含软件包 Makefile 的 SDK 源码包。

直接部署需要路由器已安装 LuCI，以及 `package/tplink-ac/Makefile` 中列出的 Python 模块、OpenSSL 和 GnuTLS 依赖。将 `tplink-ac-openwrt.tar.gz` 上传至路由器的 `/tmp` 后，以 root 身份执行：

```sh
mkdir -p /opt/tplink-ac-lab
tar -xzf /tmp/tplink-ac-openwrt.tar.gz -C /opt/tplink-ac-lab
sh /opt/tplink-ac-lab/openwrt/install.sh
```

随后在 LuCI 的“网络 → TP-LINK AC”中设置用户名、12 至 256 个字符的密码和网页端口，勾选启用并保存应用。默认网页端口为 `8765`，网页服务绑定路由器的 LAN IPv4 地址。

通过“打开 AC 管理页面”进入界面，并在 `/setup` 配置 AP 连接。需要开机启动时执行：

```sh
/etc/init.d/tplink-ac-lab enable
```

常用服务命令：

```sh
/etc/init.d/tplink-ac-lab restart
/etc/init.d/tplink-ac-lab stop
```

使用 OpenWrt SDK 构建时，将 `tplink-ac-sdk-source.tar.gz` 解压至 SDK 的 `package` 目录，再选择 `tplink-ac-core`、`tplink-ac-webui` 和 `luci-app-tplink-ac` 软件包进行编译。

## Windows 打包

在具备上述 OpenSSL DLL 的 Python 环境中安装打包依赖并执行：

```powershell
python -m pip install pyinstaller cryptography
python windows/build.py
```

输出目录为 `dist/TplinkAC/`，启动文件为 `TplinkAC.exe`。分发时保留整个输出目录；打包程序默认将运行数据保存在可执行文件旁的 `data` 目录。

## 数据与目录

连接设置保存在 `data/settings.json`，其他管理配置按功能保存在同一数据目录中。备份前先停止服务，然后复制整个数据目录；OpenWrt 部署还需备份网页访问配置 `/etc/config/tplink_ac`。

```text
src/tplink_ac/       控制器、通信服务与网页接口
web/                管理页面与静态资源
windows/            Windows 启动器与打包脚本
openwrt/            服务脚本、UCI 配置与 LuCI 页面
package/tplink-ac/  OpenWrt 软件包定义
tools/              打包与开发工具
tests/              自动化检查
run-windows.cmd     Windows 快速启动入口
```
