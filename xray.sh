#!/bin/bash
set -euo pipefail

# 默认伪装域名
REALITY_DOMAIN_DEFAULT="itunes.apple.com"
REALITY_DOMAIN="${REALITY_DOMAIN_DEFAULT}"

# 检查root权限并更新系统
root() {
    # 检查root权限
    if [[ ${EUID} -ne 0 ]]; then
        echo "Error: This script must be run as root!" 1>&2
        exit 1
    fi
    
    # 更新系统和安装基础依赖
    echo "正在更新系统和安装依赖..."
    if [ -f "/usr/bin/apt-get" ]; then
        apt-get update -y && apt-get upgrade -y
        apt-get install -y gawk curl
    else
        yum update -y && yum upgrade -y
        yum install -y epel-release gawk curl
    fi
}

# 读取伪装域名
read_reality_domain() {
    echo
    read -r -p "请输入伪装域名（直接回车使用默认：${REALITY_DOMAIN_DEFAULT}）： " input_domain
    if [[ -z "${input_domain}" ]]; then
        REALITY_DOMAIN="${REALITY_DOMAIN_DEFAULT}"
    else
        REALITY_DOMAIN="${input_domain}"
    fi
    echo "已选择伪装域名：${REALITY_DOMAIN}"
    echo
}

# 获取端口（可自定义，默认随机）
port() {
    local port1 port2 input

    # 先生成随机端口作为默认值
    port1=$(shuf -i 1024-65000 -n 1)
    while ss -ltn | grep -q ":$port1"; do
        port1=$(shuf -i 1024-65000 -n 1)
    done

    port2=$(shuf -i 1024-65000 -n 1)
    while ss -ltn | grep -q ":$port2" || [ "$port2" -eq "$port1" ]; do
        port2=$(shuf -i 1024-65000 -n 1)
    done

    echo "建议的随机端口："
    echo "  Reality TCP 端口 : ${port1}"
    echo "  XHTTP 端口       : ${port2}"
    echo

    # 手动输入 TCP 端口（可回车跳过）
    read -r -p "请输入 Reality TCP 端口（直接回车使用随机端口 ${port1}）： " input
    if [[ -n "${input}" ]]; then
        if ! [[ "${input}" =~ ^[0-9]+$ ]] || (( input < 1 || input > 65535 )); then
            echo "输入无效，继续使用随机端口 ${port1}"
        elif ss -ltn | grep -q ":$input"; then
            echo "端口 ${input} 已被占用，继续使用随机端口 ${port1}"
        else
            port1=${input}
        fi
    fi

    # 手动输入 XHTTP 端口（可回车跳过）
    read -r -p "请输入 XHTTP 端口（直接回车使用随机端口 ${port2}）： " input
    if [[ -n "${input}" ]]; then
        if ! [[ "${input}" =~ ^[0-9]+$ ]] || (( input < 1 || input > 65535 )); then
            echo "输入无效，继续使用随机端口 ${port2}"
        elif [[ "${input}" -eq "${port1}" ]]; then
            echo "端口 ${input} 与 Reality TCP 端口相同，继续使用随机端口 ${port2}"
        elif ss -ltn | grep -q ":$input"; then
            echo "端口 ${input} 已被占用，继续使用随机端口 ${port2}"
        else
            port2=${input}
        fi
    fi

    PORT1=${port1}
    PORT2=${port2}

    echo
    echo "最终使用的端口："
    echo "  Reality TCP 端口 : ${PORT1}"
    echo "  XHTTP 端口       : ${PORT2}"
    echo
}

# 是否开启 BBR
enable_bbr() {
    echo
    read -r -p "是否尝试开启 BBR 拥塞控制？[Y/n]: " answer
    case "${answer:-Y}" in
        [Nn]*)
            echo "已选择不开启 BBR。"
            echo
            return
            ;;
        *)
            echo "开始检测并尝试开启 BBR..."
            ;;
    esac

    if ! command -v sysctl >/dev/null 2>&1; then
        echo "未找到 sysctl，无法配置 BBR（已跳过）。"
        echo
        return
    fi

    # 检查内核是否支持 BBR
    if ! sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
        echo "当前内核 net.ipv4.tcp_available_congestion_control 不包含 bbr，看来不支持 BBR（已跳过）。"
        echo "如已升级内核，请重启系统后手动启用 BBR。"
        echo
        return
    fi

    # 写入 BBR 配置
    cat >/etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

    # 应用配置
    if sysctl --system >/dev/null 2>&1 || sysctl -p >/dev/null 2>&1; then
        :
    fi

    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -qw bbr; then
        echo "BBR 已启用成功。"
    else
        echo "已写入 BBR 配置，但未能确认是否启用。"
        echo "建议重启系统后使用 'sysctl net.ipv4.tcp_congestion_control' 检查。"
    fi
    echo
}

# 配置和启动Xray
xray() {
    echo "开始安装 Xray 内核..."
    # 安装Xray内核（使用官方脚本）
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

    echo "生成配置参数..."
    # 生成所需参数
    path=$(openssl rand -hex 8)
    shid=$(openssl rand -hex 8)
    uuid=$(/usr/local/bin/xray uuid)
    X25519Key=$(/usr/local/bin/xray x25519)
    PrivateKey=$(echo "$X25519Key" | grep -i '^PrivateKey:' | awk '{print $2}')
    PublicKey=$(echo "$X25519Key" | grep -E '^(PublicKey|Password):' | awk '{print $2}')

    # 配置config.json
    cat >/usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": "${PORT1}",
      "tag": "vless-tcp",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "target": "${REALITY_DOMAIN}:443",
          "serverNames": [
            "${REALITY_DOMAIN}"
          ],
          "privateKey": "${PrivateKey}",
          "shortIds": [
            "${shid}"
          ]
        }
      }
    },
    {
      "port": "${PORT2}",
      "tag": "vless-xhttp",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "flow": ""
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "path": "/${path}"
        },
        "security": "reality",
        "realitySettings": {
          "target": "${REALITY_DOMAIN}:443",
          "serverNames": [
            "${REALITY_DOMAIN}"
          ],
          "privateKey": "${PrivateKey}",
          "shortIds": [
            "${shid}"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
EOF

    echo "启动 Xray 服务..."
    systemctl enable xray.service >/dev/null 2>&1 || true
    systemctl restart xray.service

    if ! systemctl is-active --quiet xray.service; then
        echo "Xray 启动失败，请检查日志：journalctl -u xray -xe"
        exit 1
    fi

    echo "获取服务器 IP 信息..."
    # 获取IP并生成客户端配置
    HOST_IP=$(curl -s -4 https://www.cloudflare.com/cdn-cgi/trace | grep "ip" | awk -F "[=]" '{print $2}' || true)
    if [[ -z "${HOST_IP}" ]]; then
        HOST_IP=$(curl -s -6 https://www.cloudflare.com/cdn-cgi/trace | grep "ip" | awk -F "[=]" '{print $2}' || true)
    fi
    if [[ -z "${HOST_IP}" ]]; then
        HOST_IP="0.0.0.0"
    fi
    
    # 获取IP所在国家
    IP_COUNTRY=$(curl -s "https://ipinfo.io/${HOST_IP}/country" || true)
    if [[ -z "${IP_COUNTRY}" ]]; then
        IP_COUNTRY="XX"
    fi

    # 生成并保存客户端配置
    cat << EOF > /usr/local/etc/xray/config.txt

vless-tcp-reality
vless://${uuid}@${HOST_IP}:${PORT1}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_DOMAIN}&fp=chrome&pbk=${PublicKey}&sid=${shid}&type=tcp&headerType=none#${IP_COUNTRY}

vless-xhttp-reality
vless://${uuid}@${HOST_IP}:${PORT2}?encryption=none&security=reality&sni=${REALITY_DOMAIN}&fp=chrome&pbk=${PublicKey}&sid=${shid}&type=xhttp&path=%2F${path}&mode=auto#${IP_COUNTRY}
EOF

    echo
    echo "Xray 安装完成 ✅"
    echo "伪装域名：${REALITY_DOMAIN}"
    echo "配置如下（也已写入 /usr/local/etc/xray/config.txt）："
    echo "----------------------------------------------------"
    cat /usr/local/etc/xray/config.txt
    echo "----------------------------------------------------"
}

# 主函数
main() {
    root
    read_reality_domain
    port
    enable_bbr
    xray
}

# 执行脚本
main
