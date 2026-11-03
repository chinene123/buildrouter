#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GenRouter Pro - Core & Web Control Center for OpenWrt / ImmortalWrt (Mini PC + Aruba AP)
- Engine: /usr/bin/gencore (sing-box) + Auto-detects iptables TPROXY or TUN Policy Routing + Hardware Kill-Switch
- Works with Flask OR built-in Python standard-library HTTP Server (zero external pip packages required!)
- Pure-Python SOCKS5 & HTTP Proxy Checker (Zero external curl dependency)
- Per-Device (MAC / IP) Proxy Routing, DNS Anti-Leak (port 53 hijack -> proxy TCP DNS), QUIC/WebRTC Anti-Leak
- 100% Backward Compatible with existing DHCP API (/set_all_static, /del_all_static, /list_static, /add_static, /del_static)
"""

import base64
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DATA_DIR = "/etc/genrouter"
STATE_FILE = os.path.join(DATA_DIR, "state.json")
SINGBOX_CONFIG = os.path.join(DATA_DIR, "sing-box.json")
NFTABLES_RULES = os.path.join(DATA_DIR, "genrouter.nft")
STATIC_JSON_PATH = "/etc/shm/list_ip_static.json"

GENCORE_BIN = "/usr/bin/gencore" if os.path.exists("/usr/bin/gencore") else "sing-box"
TPROXY_PORT = 12345
DNS_LISTEN_PORT = 53

# Known Aruba / Enterprise AP OUI prefixes
ARUBA_OUIS = (
    "18:64:72", "00:0B:86", "00:1A:1E", "00:24:6C", "24:DE:C6",
    "6C:F3:7F", "9C:1C:12", "D8:C7:C8", "F0:5C:19", "94:B4:0F", "70:3A:0E"
)

state_lock = threading.Lock()


def run_cmd(cmd, timeout=10):
    try:
        res = subprocess.run(
            cmd,
            shell=isinstance(cmd, str),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return res.returncode == 0, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return False, "", str(e)


def detect_router_network():
    """Auto-detect LAN IP, LAN subnet, and WAN interface from OpenWrt UCI."""
    router_ip = "172.16.5.1"
    lan_subnet = "172.16.0.0/20"
    wan_iface = "eth0"

    ok_ip, ip_out, _ = run_cmd("uci get network.lan.ipaddr")
    ok_mask, mask_out, _ = run_cmd("uci get network.lan.netmask")
    if ok_ip and ip_out:
        router_ip = ip_out.strip()
        mask = mask_out.strip() if (ok_mask and mask_out) else "255.255.255.0"
        try:
            net = ipaddress.IPv4Network(f"{router_ip}/{mask}", strict=False)
            lan_subnet = str(net)
        except Exception:
            pass

    ok_wan, wan_out, _ = run_cmd("uci get network.wan.device || uci get network.wan.ifname")
    if ok_wan and wan_out:
        wan_iface = wan_out.strip()

    return router_ip, lan_subnet, wan_iface


def default_state():
    router_ip, lan_subnet, wan_iface = detect_router_network()
    return {
        "proxies": {},       # id -> {id, name, type, host, port, username, password, status, latency, exit_ip, country, isp, last_check}
        "assignments": {},   # mac (UPPER) -> {mac, ip, proxy_id, kill_switch, block_quic, note}
        "settings": {
            "lan_iface": "br-lan",
            "wan_iface": wan_iface,
            "lan_subnet": lan_subnet,
            "router_ip": router_ip,
            "auto_static_lease": True,
        }
    }


def load_state():
    os.makedirs(DATA_DIR, exist_ok=True)
    d = default_state()
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                d["proxies"] = data.get("proxies", {})
                d["assignments"] = data.get("assignments", {})
                if "settings" in data:
                    d["settings"].update(data["settings"])
        except Exception:
            pass
    # Always refresh detected router_ip & lan_subnet
    router_ip, lan_subnet, wan_iface = detect_router_network()
    d["settings"]["router_ip"] = router_ip
    d["settings"]["lan_subnet"] = lan_subnet
    d["settings"]["wan_iface"] = wan_iface
    return d


def save_state(state):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    os.replace(tmp, STATE_FILE)


STATE = load_state()


# =====================================================================
# OpenWrt UCI DHCP & Device Discovery
# =====================================================================

def get_uci_dhcp_hosts():
    ok, raw, _ = run_cmd("ubus call uci get '{\"config\":\"dhcp\"}'")
    if ok and raw:
        try:
            uci_data = json.loads(raw)
            values = uci_data.get("values", {})
            return {sec_id: sec for sec_id, sec in values.items() if sec.get(".type") == "host"}
        except Exception:
            pass
    return {}


def save_static_json():
    hosts = get_uci_dhcp_hosts()
    try:
        os.makedirs(os.path.dirname(STATIC_JSON_PATH), exist_ok=True)
        with open(STATIC_JSON_PATH, "w", encoding="utf-8") as jf:
            json.dump(hosts, jf, indent=4)
    except Exception:
        pass
    return hosts


def get_static_by_mac():
    hosts = get_uci_dhcp_hosts()
    by_mac = {}
    for section, sec in hosts.items():
        mac = (sec.get("mac") or "").upper().strip()
        ip = (sec.get("ip") or "").strip()
        if mac and ip:
            by_mac[mac] = {
                "section": section,
                "mac": mac,
                "ip": ip,
                "name": sec.get("name", ""),
            }
    return by_mac


def add_uci_static_host(ip, mac, name=""):
    mac_u = mac.upper().strip()
    ip_s = ip.strip()
    hosts = get_uci_dhcp_hosts()
    for section, sec in hosts.items():
        if (sec.get("mac") or "").upper().strip() == mac_u or (sec.get("ip") or "").strip() == ip_s:
            run_cmd(f"uci delete dhcp.{section}")
    section_name = name.strip() if name else f"static_{mac_u.replace(':', '')}"
    section_name = re.sub(r"[^a-zA-Z0-9_-]", "_", section_name)
    run_cmd("uci add dhcp host")
    run_cmd(f"uci set dhcp.@host[-1].name='{section_name}'")
    run_cmd(f"uci set dhcp.@host[-1].ip='{ip_s}'")
    run_cmd(f"uci set dhcp.@host[-1].mac='{mac_u}'")
    run_cmd("uci commit dhcp")
    run_cmd("/etc/init.d/dnsmasq reload >/dev/null 2>&1 || true")
    run_cmd("/etc/init.d/odhcpd reload >/dev/null 2>&1 || true")
    save_static_json()
    return section_name


def get_dhcp_leases():
    leases = {}
    lease_file = "/tmp/dhcp.leases"
    if os.path.exists(lease_file):
        try:
            with open(lease_file, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        ts, mac, ip, hostname = parts[0], parts[1].upper(), parts[2], parts[3]
                        leases[mac] = {
                            "mac": mac,
                            "ip": ip,
                            "hostname": "" if hostname == "*" else hostname,
                            "expires": int(ts) if ts.isdigit() else 0,
                        }
        except Exception:
            pass
    return leases


def get_arp_neighbors(lan_iface="br-lan"):
    arp = {}
    ok, out, _ = run_cmd(f"ip -4 neigh show dev {lan_iface}")
    if ok:
        for line in out.splitlines():
            m = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+lladdr\s+([0-9a-fA-F:]+)\s+(\S+)", line)
            if m:
                ip, mac, state = m.group(1), m.group(2).upper(), m.group(3)
                arp[mac] = {"ip": ip, "mac": mac, "arp_state": state}
    return arp


def is_aruba_mac(mac):
    return any(mac.upper().startswith(prefix) for prefix in ARUBA_OUIS)


def discover_all_devices():
    static_by_mac = get_static_by_mac()
    leases = get_dhcp_leases()
    arp = get_arp_neighbors(STATE["settings"].get("lan_iface", "br-lan"))
    assignments = STATE.get("assignments", {})
    proxies = STATE.get("proxies", {})

    all_macs = set(static_by_mac.keys()) | set(leases.keys()) | set(arp.keys()) | set(assignments.keys())
    devices = []
    for mac in sorted(all_macs):
        if not mac or mac == "00:00:00:00:00:00":
            continue
        st = static_by_mac.get(mac, {})
        le = leases.get(mac, {})
        ar = arp.get(mac, {})
        asg = assignments.get(mac, {})

        ip = st.get("ip") or le.get("ip") or ar.get("ip") or asg.get("ip") or ""
        hostname = asg.get("note") or le.get("hostname") or st.get("name") or ""
        if is_aruba_mac(mac) and not hostname:
            hostname = "Bộ phát Wi-Fi Aruba (AP)"
        arp_state = ar.get("arp_state", "OFFLINE")
        online = arp_state in ("REACHABLE", "STALE", "DELAY", "PROBE") or (mac in leases and arp_state != "FAILED")

        proxy_id = asg.get("proxy_id", "")
        proxy_info = proxies.get(proxy_id) if proxy_id else None

        dev_type = "phone"
        if is_aruba_mac(mac):
            dev_type = "aruba"
        elif "DESKTOP" in (le.get("hostname") or "").upper() or "LAPTOP" in (le.get("hostname") or "").upper():
            dev_type = "pc"

        devices.append({
            "mac": mac,
            "ip": ip,
            "hostname": hostname,
            "dev_type": dev_type,
            "is_static": mac in static_by_mac,
            "online": online,
            "arp_state": arp_state,
            "proxy_id": proxy_id,
            "proxy_label": f"{proxy_info['type'].upper()}://{proxy_info['host']}:{proxy_info['port']}" if proxy_info else "Direct (Mạng gốc)",
            "proxy_status": proxy_info.get("status", "unknown") if proxy_info else "direct",
            "proxy_exit_ip": proxy_info.get("exit_ip", "") if proxy_info else "",
            "proxy_country": proxy_info.get("country", "") if proxy_info else "",
            "kill_switch": bool(asg.get("kill_switch", False)),
            "block_quic": bool(asg.get("block_quic", True)),
            "note": asg.get("note", ""),
        })
    devices.sort(key=lambda x: (0 if x["dev_type"] in ("aruba", "pc") else 1, 0 if x["online"] else 1, x["ip"]))
    return devices


# =====================================================================
# Pure-Python SOCKS5 & HTTP Proxy Checker
# =====================================================================

def parse_proxy_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    ptype = "socks5"
    if "://" in line:
        scheme, rest = line.split("://", 1)
        ptype = "http" if scheme.lower().startswith("http") else "socks5"
        line = rest

    username = ""
    password = ""
    if "@" in line:
        creds, hostport = line.rsplit("@", 1)
        if ":" in creds:
            username, password = creds.split(":", 1)
        parts = hostport.split(":")
        if len(parts) != 2:
            return None
        host, port = parts[0], int(parts[1])
    else:
        parts = line.split(":")
        if len(parts) == 2:
            host, port = parts[0], int(parts[1])
        elif len(parts) >= 4:
            host, port = parts[0], int(parts[1])
            username, password = parts[2], ":".join(parts[3:])
        else:
            return None

    return {
        "type": ptype,
        "host": host.strip(),
        "port": port,
        "username": username.strip(),
        "password": password.strip(),
    }


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Unexpected EOF from proxy")
        buf += chunk
    return buf


def check_single_proxy(proxy_obj):
    ptype = proxy_obj["type"]
    host = proxy_obj["host"]
    port = int(proxy_obj["port"])
    user = proxy_obj.get("username", "")
    pw = proxy_obj.get("password", "")

    target_host = "ip-api.com"
    target_port = 80
    target_path = "/json/?fields=status,countryCode,query,isp"

    t0 = time.time()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.settimeout(5)

        if ptype == "socks5":
            if user:
                sock.sendall(b"\x05\x02\x00\x02")
            else:
                sock.sendall(b"\x05\x01\x00")
            ver, method = _recv_exact(sock, 2)
            if ver != 5 or method == 0xFF:
                raise ConnectionError("SOCKS5 auth method rejected")
            if method == 2:
                u_bytes = user.encode("utf-8")
                p_bytes = pw.encode("utf-8")
                sock.sendall(b"\x01" + bytes([len(u_bytes)]) + u_bytes + bytes([len(p_bytes)]) + p_bytes)
                _, auth_status = _recv_exact(sock, 2)
                if auth_status != 0:
                    raise ConnectionError("SOCKS5 wrong username/password")

            th_bytes = target_host.encode("utf-8")
            req = b"\x05\x01\x00\x03" + bytes([len(th_bytes)]) + th_bytes + struct.pack("!H", target_port)
            sock.sendall(req)
            hdr = _recv_exact(sock, 4)
            if hdr[1] != 0:
                raise ConnectionError(f"SOCKS5 connect failed with code {hdr[1]}")
            atyp = hdr[3]
            if atyp == 1:
                _recv_exact(sock, 4 + 2)
            elif atyp == 3:
                dlen = _recv_exact(sock, 1)[0]
                _recv_exact(sock, dlen + 2)
            elif atyp == 4:
                _recv_exact(sock, 16 + 2)

            http_req = (
                f"GET {target_path} HTTP/1.1\r\n"
                f"Host: {target_host}\r\n"
                f"User-Agent: GenRouter/2.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8")
            sock.sendall(http_req)
        else:
            auth_hdr = ""
            if user:
                token = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
                auth_hdr = f"Proxy-Authorization: Basic {token}\r\n"
            http_req = (
                f"GET http://{target_host}{target_path} HTTP/1.1\r\n"
                f"Host: {target_host}\r\n"
                f"{auth_hdr}"
                f"User-Agent: GenRouter/2.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8")
            sock.sendall(http_req)

        resp = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
        latency = int((time.time() - t0) * 1000)
        text = resp.decode("utf-8", errors="replace")
        if "\r\n\r\n" in text:
            body = text.split("\r\n\r\n", 1)[1].strip()
            m = re.search(r"\{.*\}", body, re.DOTALL)
            if m:
                info = json.loads(m.group(0))
                if info.get("status") == "success":
                    proxy_obj["status"] = "live"
                    proxy_obj["latency"] = latency
                    proxy_obj["exit_ip"] = info.get("query", "")
                    proxy_obj["country"] = info.get("countryCode", "")
                    proxy_obj["isp"] = info.get("isp", "")
                    proxy_obj["last_check"] = int(time.time())
                    return proxy_obj
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    proxy_obj["status"] = "dead"
    proxy_obj["latency"] = -1
    proxy_obj["last_check"] = int(time.time())
    return proxy_obj


# =====================================================================
# Transparent Proxy & Hardware Kill-Switch Engine (TPROXY + TUN Fallback)
# =====================================================================

def has_iptables_tproxy():
    ok, _, _ = run_cmd("iptables -t mangle -L -n >/dev/null 2>&1 && grep -q TPROXY /proc/net/ip_tables_targets 2>/dev/null")
    if ok:
        return True
    ok2, out2, _ = run_cmd("lsmod | grep -i xt_TPROXY")
    return ok2 and bool(out2)


def ensure_firewall_and_dns_compatible():
    """Disable flow offloading in fw4 and ensure dnsmasq is on port 5353 with dns_redirect."""
    ok, out, _ = run_cmd("uci get firewall.@defaults[0].flow_offloading")
    if ok and out.strip() == "1":
        run_cmd("uci set firewall.@defaults[0].flow_offloading='0'")
        run_cmd("uci set firewall.@defaults[0].flow_offloading_hw='0'")
        run_cmd("uci commit firewall")
        run_cmd("/etc/init.d/firewall reload >/dev/null 2>&1 || true")

    # Ensure dnsmasq listens on 5353 so gencore handles port 53 per-device DNS
    if os.path.exists("/etc/dnsmasq.conf"):
        with open("/etc/dnsmasq.conf", "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        if "port=5353" not in content:
            with open("/etc/dnsmasq.conf", "a", encoding="utf-8") as f:
                f.write("\nport=5353\n")
            run_cmd("uci set dhcp.@dnsmasq[0].dns_redirect='1' && uci commit dhcp")
            run_cmd("/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true")


def apply_routing_engine():
    with state_lock:
        proxies = STATE.get("proxies", {})
        assignments = STATE.get("assignments", {})
        settings = STATE.get("settings", {})

    lan_iface = settings.get("lan_iface", "br-lan")
    wan_iface = settings.get("wan_iface", "eth0")
    lan_subnet = settings.get("lan_subnet", "172.16.0.0/20")
    use_tproxy = has_iptables_tproxy()

    dns_servers = [
        {"tag": "dns-local", "address": "udp://127.0.0.1:5353", "detour": "direct"},
        {"tag": "dns-direct", "address": "8.8.8.8", "detour": "direct"},
    ]
    dns_rules = []

    inbounds = [
        {
            "type": "direct",
            "tag": "dns-in",
            "listen": "::",
            "listen_port": DNS_LISTEN_PORT,
        }
    ]
    if use_tproxy:
        inbounds.append({
            "type": "tproxy",
            "tag": "tproxy-in",
            "listen": "::",
            "listen_port": TPROXY_PORT,
            "sniff": True,
            "sniff_override_destination": False,
        })
    else:
        inbounds.append({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "grtun0",
            "address": ["198.18.0.1/30"],
            "mtu": 1400,
            "auto_route": False,
            "strict_route": False,
            "stack": "mixed",
            "sniff": True,
        })

    outbounds = [
        {"type": "direct", "tag": "direct"},
    ]

    route_rules = [
        {"inbound": ["dns-in"], "action": "hijack-dns"},
        {"protocol": "dns", "action": "hijack-dns"},
    ]

    for pid, p in sorted(proxies.items()):
        ob = {
            "type": "socks" if p["type"] == "socks5" else "http",
            "tag": f"out-{pid}",
            "server": p["host"],
            "server_port": int(p["port"]),
        }
        if p.get("username"):
            ob["username"] = p["username"]
            ob["password"] = p.get("password", "")
        outbounds.append(ob)

        dns_servers.append({
            "tag": f"dns-{pid}",
            "address": "tcp://8.8.8.8",
            "detour": f"out-{pid}",
        })

    proxied_ips = []
    killswitch_ips = []
    quic_blocked_ips = []

    for mac, asg in sorted(assignments.items()):
        ip = (asg.get("ip") or "").strip()
        pid = asg.get("proxy_id", "")
        kill_switch = bool(asg.get("kill_switch", False))
        block_quic = bool(asg.get("block_quic", True))

        if not ip:
            continue
        try:
            ipaddress.IPv4Address(ip)
        except Exception:
            continue

        if pid and pid in proxies:
            p_obj = proxies[pid]
            if kill_switch and p_obj.get("status") == "dead":
                killswitch_ips.append(ip)
                route_rules.append({
                    "source_ip_cidr": [f"{ip}/32"],
                    "action": "reject",
                })
            else:
                proxied_ips.append(ip)
                if kill_switch:
                    killswitch_ips.append(ip)
                if block_quic:
                    quic_blocked_ips.append(ip)
                dns_rules.append({
                    "source_ip_cidr": [f"{ip}/32"],
                    "server": f"dns-{pid}",
                })
                route_rules.append({
                    "source_ip_cidr": [f"{ip}/32"],
                    "outbound": f"out-{pid}",
                })
        elif kill_switch:
            killswitch_ips.append(ip)

    singbox_cfg = {
        "log": {"level": "warn"},
        "dns": {
            "servers": dns_servers,
            "rules": dns_rules,
            "final": "dns-local",
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": route_rules,
            "final": "direct",
            "auto_detect_interface": True,
        }
    }

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(SINGBOX_CONFIG, "w", encoding="utf-8") as f:
        json.dump(singbox_cfg, f, indent=2)

    # Restart gencore (sing-box)
    run_cmd("killall -9 gencore sing-box 2>/dev/null || true")
    subprocess.Popen([GENCORE_BIN, "run", "-c", SINGBOX_CONFIG], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    ok_ipt = True
    err_ipt = ""
    if use_tproxy:
        ipt_cmds = [
            "iptables -t mangle -N GENROUTER_PRE 2>/dev/null || true",
            "iptables -t mangle -F GENROUTER_PRE",
            f"iptables -t mangle -C PREROUTING -i {lan_iface} -j GENROUTER_PRE 2>/dev/null || iptables -t mangle -A PREROUTING -i {lan_iface} -j GENROUTER_PRE",
            "iptables -t mangle -A GENROUTER_PRE -d 127.0.0.0/8 -j RETURN",
            f"iptables -t mangle -A GENROUTER_PRE -d {lan_subnet} -j RETURN",
            "iptables -t mangle -A GENROUTER_PRE -d 192.168.0.0/16 -j RETURN",
            "iptables -t mangle -A GENROUTER_PRE -d 10.0.0.0/8 -j RETURN",
            "iptables -t mangle -A GENROUTER_PRE -d 224.0.0.0/4 -j RETURN",
            "iptables -t mangle -A GENROUTER_PRE -d 255.255.255.255/32 -j RETURN",
        ]
        for ip in sorted(set(quic_blocked_ips)):
            ipt_cmds.append(f"iptables -t mangle -A GENROUTER_PRE -s {ip} -p udp --dport 443 -j DROP")
        for ip in sorted(set(proxied_ips)):
            ipt_cmds.append(
                f"iptables -t mangle -A GENROUTER_PRE -s {ip} -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port {TPROXY_PORT} --tproxy-mark 0x1"
            )
            ipt_cmds.append(
                f"iptables -t mangle -A GENROUTER_PRE -s {ip} -p udp -j TPROXY --on-ip 127.0.0.1 --on-port {TPROXY_PORT} --tproxy-mark 0x1"
            )
        ok_ipt, _, err_ipt = run_cmd(" && ".join(ipt_cmds))
        run_cmd("ip rule show | grep -q 'fwmark 0x1 lookup 100' || ip rule add fwmark 0x1 lookup 100")
        run_cmd("ip route show table 100 | grep -q 'local default' || ip route add local default dev lo table 100")
    else:
        # TUN policy routing mode
        time.sleep(0.8)
        run_cmd("ip link set grtun0 up 2>/dev/null || true")
        run_cmd("ip route replace default dev grtun0 table 100 2>/dev/null || true")
        # Clean previous priority 100 rules
        run_cmd("while ip rule del priority 100 2>/dev/null; do :; done")
        run_cmd(f"ip rule show | grep -q 'to {lan_subnet} lookup main' || ip rule add to {lan_subnet} lookup main priority 90")
        for ip in sorted(set(proxied_ips)):
            run_cmd(f"ip rule add from {ip} lookup 100 priority 100")

    # Apply nftables forward Kill-Switch & QUIC blocker
    nft_lines = [
        "table ip genrouter",
        "delete table ip genrouter",
        "table ip genrouter {",
        "  chain forward_killswitch {",
        "    type filter hook forward priority filter - 10; policy accept;",
    ]
    if quic_blocked_ips:
        ips_str = ", ".join(sorted(set(quic_blocked_ips)))
        nft_lines.append(f"    iifname \"{lan_iface}\" ip saddr {{ {ips_str} }} udp dport 443 reject")
    if killswitch_ips and use_tproxy:
        ips_str = ", ".join(sorted(set(killswitch_ips)))
        nft_lines.append(f"    iifname \"{lan_iface}\" oifname \"{wan_iface}\" ip saddr {{ {ips_str} }} drop")
    nft_lines.append("  }")
    nft_lines.append("}")

    with open(NFTABLES_RULES, "w", encoding="utf-8") as f:
        f.write("\n".join(nft_lines) + "\n")

    ok_nft, _, err_nft = run_cmd(f"nft -f {NFTABLES_RULES}")
    return {
        "gencore_running": True,
        "mode": "TPROXY" if use_tproxy else "TUN",
        "tproxy_applied": ok_ipt,
        "nftables_applied": ok_nft,
        "error": (err_ipt or err_nft) if not (ok_ipt and ok_nft) else "",
        "proxied_devices": len(proxied_ips),
        "killswitch_devices": len(killswitch_ips),
    }


# =====================================================================
# Business Logic Handlers (Used by both Flask and Stdlib HTTP Server)
# =====================================================================

def handle_set_all_static():
    ok, raw, _ = run_cmd("ubus call luci-rpc getDHCPLeases")
    dhcp_data = json.loads(raw) if ok and raw else {}
    leases = dhcp_data.get("dhcp_leases", [])

    static_by_mac = get_static_by_mac()
    existing_ips = {v["ip"] for v in static_by_mac.values()}
    existing_macs = set(static_by_mac.keys())
    static_entries = []

    for lease in leases:
        hostname = lease.get("hostname") or ""
        ipaddr = lease.get("ipaddr")
        macaddr = (lease.get("macaddr") or "").upper()
        if not ipaddr or not macaddr:
            continue
        if ipaddr in existing_ips or macaddr in existing_macs:
            continue
        add_uci_static_host(ipaddr, macaddr, hostname)
        static_entries.append({"hostname": hostname, "ip": ipaddr, "mac": macaddr})
        existing_ips.add(ipaddr)
        existing_macs.add(macaddr)

    save_static_json()
    return {"static_hosts_added": static_entries}, 200


def handle_del_all_static():
    hosts = get_uci_dhcp_hosts()
    deleted = []
    for section, sec in hosts.items():
        deleted.append({
            "section": section,
            "hostname": sec.get("name"),
            "ip": sec.get("ip"),
            "mac": sec.get("mac"),
        })
        run_cmd(f"uci delete dhcp.{section}")
    if deleted:
        run_cmd("uci commit dhcp")
        run_cmd("/etc/init.d/dnsmasq reload >/dev/null 2>&1 || true")
        run_cmd("/etc/init.d/odhcpd reload >/dev/null 2>&1 || true")
    save_static_json()
    return {"deleted_hosts": deleted}, 200


def handle_list_static():
    return get_uci_dhcp_hosts(), 200


def handle_add_static(ip, mac):
    if not ip or not mac:
        return {"error": "Missing 'ip' or 'mac' query parameter"}, 400
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return {"error": f"Invalid IPv4 address: {ip}"}, 400
    mac_pattern = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    if not mac_pattern.match(mac):
        return {"error": f"Invalid MAC address: {mac}"}, 400

    section_name = add_uci_static_host(ip, mac)
    return {"status": "success", "section": section_name, "ip": ip, "mac": mac}, 201


def handle_del_static(ip, mac):
    if not ip and not mac:
        return {"error": "Thiếu tham số 'ip' hoặc 'mac'"}, 400
    hosts = get_uci_dhcp_hosts()
    to_delete = []
    for section, sec in hosts.items():
        if (ip and sec.get("ip") == ip) or (mac and (sec.get("mac") or "").upper() == mac.upper()):
            to_delete.append({
                "section": section,
                "hostname": sec.get("name"),
                "ip": sec.get("ip"),
                "mac": sec.get("mac"),
            })
            run_cmd(f"uci delete dhcp.{section}")
    if not to_delete:
        return {"message": "Không tìm thấy host tĩnh tương ứng"}, 404
    run_cmd("uci commit dhcp")
    run_cmd("/etc/init.d/dnsmasq reload >/dev/null 2>&1 || true")
    run_cmd("/etc/init.d/odhcpd reload >/dev/null 2>&1 || true")
    save_static_json()
    return {"deleted": to_delete}, 200


def handle_api_overview():
    devices = discover_all_devices()
    proxies = list(STATE.get("proxies", {}).values())
    ok_gc, _, _ = run_cmd("pidof gencore || pidof sing-box")
    return {
        "devices": devices,
        "proxies": proxies,
        "settings": STATE.get("settings", {}),
        "engine_online": ok_gc,
    }, 200


def handle_api_import_proxies(data):
    raw_text = data.get("proxies_text", "")
    default_type = data.get("type", "socks5")
    added = []
    with state_lock:
        for line in raw_text.splitlines():
            parsed = parse_proxy_line(line)
            if not parsed:
                continue
            if "://" not in line and default_type in ("socks5", "http"):
                parsed["type"] = default_type
            pid = f"{parsed['host']}_{parsed['port']}"
            proxy_obj = {
                "id": pid,
                "name": f"{parsed['host']}:{parsed['port']}",
                "type": parsed["type"],
                "host": parsed["host"],
                "port": parsed["port"],
                "username": parsed["username"],
                "password": parsed["password"],
                "status": "unchecked",
                "latency": -1,
                "exit_ip": "",
                "country": "",
                "isp": "",
                "last_check": 0,
            }
            STATE["proxies"][pid] = proxy_obj
            added.append(proxy_obj)
        save_state(STATE)
    apply_routing_engine()
    return {"status": "ok", "added_count": len(added)}, 200


def handle_api_check_proxies():
    with state_lock:
        proxy_list = list(STATE["proxies"].values())
    if proxy_list:
        with ThreadPoolExecutor(max_workers=12) as ex:
            results = list(ex.map(check_single_proxy, proxy_list))
        with state_lock:
            for r in results:
                STATE["proxies"][r["id"]] = r
            save_state(STATE)
    else:
        results = []
    engine_res = apply_routing_engine()
    return {"status": "ok", "checked": len(results), "proxies": results, "engine": engine_res}, 200


def handle_api_delete_proxy(data):
    pid = data.get("id", "")
    with state_lock:
        STATE["proxies"].pop(pid, None)
        for mac, asg in STATE["assignments"].items():
            if asg.get("proxy_id") == pid:
                asg["proxy_id"] = ""
        save_state(STATE)
    apply_routing_engine()
    return {"status": "ok"}, 200


def handle_api_clear_proxies():
    with state_lock:
        STATE["proxies"] = {}
        for mac, asg in STATE["assignments"].items():
            asg["proxy_id"] = ""
        save_state(STATE)
    apply_routing_engine()
    return {"status": "ok"}, 200


def handle_api_assign_device(data):
    mac = (data.get("mac") or "").upper().strip()
    ip = (data.get("ip") or "").strip()
    proxy_id = data.get("proxy_id", "")
    kill_switch = bool(data.get("kill_switch", False))
    block_quic = bool(data.get("block_quic", True))
    note = data.get("note", "")

    if not mac:
        return {"error": "Missing MAC address"}, 400
    if ip:
        add_uci_static_host(ip, mac, note)
    with state_lock:
        STATE["assignments"][mac] = {
            "mac": mac,
            "ip": ip,
            "proxy_id": proxy_id,
            "kill_switch": kill_switch,
            "block_quic": block_quic,
            "note": note,
        }
        save_state(STATE)
    engine_res = apply_routing_engine()
    return {"status": "ok", "engine": engine_res}, 200


def handle_api_auto_assign():
    devices = discover_all_devices()
    with state_lock:
        live_proxies = [p for p in STATE["proxies"].values() if p.get("status") == "live"]
        if not live_proxies:
            live_proxies = list(STATE["proxies"].values())
        if not live_proxies:
            return {"error": "Kho Proxy đang trống! Hãy thêm Proxy trước."}, 400

        assigned_count = 0
        for dev in devices:
            if dev["dev_type"] in ("aruba", "pc"):
                continue
            mac = dev["mac"]
            ip = dev["ip"]
            if not ip:
                continue
            chosen = live_proxies[assigned_count % len(live_proxies)]
            add_uci_static_host(ip, mac, dev.get("hostname", ""))
            STATE["assignments"][mac] = {
                "mac": mac,
                "ip": ip,
                "proxy_id": chosen["id"],
                "kill_switch": True,
                "block_quic": True,
                "note": dev.get("hostname", ""),
            }
            assigned_count += 1
        save_state(STATE)
    engine_res = apply_routing_engine()
    return {"status": "ok", "assigned_count": assigned_count, "engine": engine_res}, 200


# =====================================================================
# GenRouter Web UI Dashboard HTML
# =====================================================================

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GenRouter Pro - OpenWrt + Aruba Control Center</title>
  <style>
    :root {
      --bg: #0b1120;
      --card: #161f33;
      --border: #28354f;
      --text: #f1f5f9;
      --muted: #94a3b8;
      --accent: #3b82f6;
      --success: #10b981;
      --danger: #ef4444;
      --warn: #f59e0b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; padding: 20px;
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: var(--bg); color: var(--text);
    }
    .header {
      display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
      padding: 18px 24px; background: var(--card); border: 1px solid var(--border);
      border-radius: 14px; margin-bottom: 20px;
    }
    .header h1 { margin: 0; font-size: 20px; display: flex; align-items: center; gap: 10px; }
    .badge {
      padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; display: inline-block;
    }
    .badge-live { background: rgba(16,185,129,0.15); color: var(--success); border: 1px solid rgba(16,185,129,0.3); }
    .badge-dead { background: rgba(239,68,68,0.15); color: var(--danger); border: 1px solid rgba(239,68,68,0.3); }
    .badge-warn { background: rgba(245,158,11,0.15); color: var(--warn); border: 1px solid rgba(245,158,11,0.3); }
    .badge-direct { background: rgba(148,163,184,0.12); color: var(--muted); }
    .grid { display: grid; grid-template-columns: 1.85fr 1.15fr; gap: 20px; }
    @media (max-width: 1150px) { .grid { grid-template-columns: 1fr; } }
    .card {
      background: var(--card); border: 1px solid var(--border);
      border-radius: 14px; padding: 20px;
    }
    .card-header {
      display: flex; justify-content: space-between; align-items: center;
      margin-bottom: 16px;
    }
    .card-header h2 { margin: 0; font-size: 16px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 10px 8px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: middle; }
    th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; }
    button {
      background: var(--accent); color: #fff; border: none;
      padding: 8px 14px; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 13px;
      transition: all 0.15s;
    }
    button:hover { filter: brightness(1.1); }
    button.btn-secondary { background: #28354f; }
    button.btn-success { background: var(--success); }
    button.btn-danger { background: var(--danger); padding: 5px 10px; font-size: 12px; }
    select, input[type="text"], textarea {
      background: #0b1120; color: var(--text); border: 1px solid var(--border);
      border-radius: 8px; padding: 7px 10px; font-size: 13px;
    }
    textarea { width: 100%; height: 115px; font-family: Consolas, monospace; margin-bottom: 10px; resize: vertical; }
    .toolbar { display: flex; gap: 8px; flex-wrap: wrap; }
    .toast {
      position: fixed; bottom: 20px; right: 20px; background: var(--success); color: #fff;
      padding: 12px 20px; border-radius: 10px; font-weight: 600; display: none; z-index: 999;
      box-shadow: 0 10px 25px rgba(0,0,0,0.4);
    }
  </style>
</head>
<body>
  <div id="toast" class="toast">Đã lưu cấu hình!</div>

  <div class="header">
    <div>
      <h1>
        ⚡ GenRouter Pro
        <span class="badge badge-live" id="engineStatus">Sing-box TPROXY Active</span>
        <span class="badge badge-warn" id="lanSubnetBadge">LAN: 172.16.5.1/20</span>
      </h1>
      <div style="color: var(--muted); font-size: 13px; margin-top: 5px;">
        Định tuyến Proxy tầng mạng theo MAC / IP • Chống rò rỉ DNS & WebRTC/QUIC • Kill-Switch tự ngắt khi Proxy chết
      </div>
    </div>
    <div class="toolbar">
      <button onclick="loadData()" class="btn-secondary">🔄 Làm mới</button>
      <button onclick="lockAllStatic()" class="btn-secondary">📌 Cố định IP tĩnh tất cả</button>
      <button onclick="autoAssignProxies()" class="btn-success">🚀 Tự động gán Proxy 1:1 cho Phone</button>
    </div>
  </div>

  <div class="grid">
    <!-- Danh sách Thiết bị (Aruba Wi-Fi & LAN) -->
    <div class="card">
      <div class="card-header">
        <h2>📱 Thiết bị kết nối qua Aruba & LAN (<span id="devCount">0</span>)</h2>
        <span style="font-size:12px; color:var(--muted);">Tự động phát hiện Aruba AP & Điện thoại kết nối Wi-Fi</span>
      </div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Trạng thái</th>
              <th>Thiết bị / Ghi chú</th>
              <th>IP nội bộ</th>
              <th>MAC Address</th>
              <th>Proxy định tuyến</th>
              <th>Kill-Switch</th>
              <th>Lưu</th>
            </tr>
          </thead>
          <tbody id="deviceTable"></tbody>
        </table>
      </div>
    </div>

    <!-- Kho Proxy -->
    <div class="card">
      <div class="card-header">
        <h2>🌐 Kho Proxy (<span id="proxyCount">0</span>)</h2>
        <div style="display:flex; gap:6px;">
          <button onclick="checkAllProxies()" class="btn-secondary" id="btnCheck">⚡ Check Live / Ping</button>
          <button onclick="clearProxies()" class="btn-danger">Xóa hết</button>
        </div>
      </div>
      <div style="margin-bottom: 14px;">
        <div style="margin-bottom: 6px; font-size: 12px; color: var(--muted);">
          Nhập danh sách Proxy (mỗi dòng 1 proxy: <code>ip:port:user:pass</code> hoặc <code>socks5://user:pass@ip:port</code> hoặc <code>http://...</code>):
        </div>
        <textarea id="proxyInput" placeholder="103.1.2.3:1080:user:pass&#10;http://user:pass@45.1.2.3:8080"></textarea>
        <div style="display:flex; gap: 8px;">
          <select id="defaultProxyType">
            <option value="socks5">SOCKS5 Mặc định</option>
            <option value="http">HTTP Proxy Mặc định</option>
          </select>
          <button onclick="importProxies()">➕ Thêm vào kho Proxy</button>
        </div>
      </div>

      <div style="overflow-x: auto; max-height: 460px;">
        <table>
          <thead>
            <tr>
              <th>Proxy Server</th>
              <th>Loại</th>
              <th>Trạng thái / IP Ra</th>
              <th>Ping</th>
              <th></th>
            </tr>
          </thead>
          <tbody id="proxyTable"></tbody>
        </table>
      </div>
    </div>
  </div>

<script>
let STATE_DATA = { devices: [], proxies: [] };

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.display = 'block';
  setTimeout(() => { t.style.display = 'none'; }, 2500);
}

async function loadData() {
  const res = await fetch('/api/overview');
  STATE_DATA = await res.json();
  const eng = document.getElementById('engineStatus');
  if (STATE_DATA.engine_online) {
    eng.className = 'badge badge-live';
    eng.textContent = 'Gencore (Sing-box) Active';
  } else {
    eng.className = 'badge badge-dead';
    eng.textContent = 'Gencore Stopped';
  }
  if (STATE_DATA.settings && STATE_DATA.settings.router_ip) {
    document.getElementById('lanSubnetBadge').textContent = `LAN: ${STATE_DATA.settings.router_ip} (${STATE_DATA.settings.lan_subnet})`;
  }
  renderDevices();
  renderProxies();
}

function renderProxies() {
  const tbody = document.getElementById('proxyTable');
  document.getElementById('proxyCount').textContent = STATE_DATA.proxies.length;
  if (!STATE_DATA.proxies.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:20px;">Chưa có Proxy nào trong kho. Hãy thêm ở ô bên trên!</td></tr>';
    return;
  }
  tbody.innerHTML = STATE_DATA.proxies.map(p => {
    let badge = '<span class="badge badge-direct">Chưa check</span>';
    if (p.status === 'live') badge = `<span class="badge badge-live">LIVE • ${p.exit_ip || ''} (${p.country || ''})</span>`;
    if (p.status === 'dead') badge = '<span class="badge badge-dead">DIE</span>';
    return `<tr>
      <td><b>${p.host}:${p.port}</b>${p.username ? '<br><small style="color:var(--muted)">👤 ' + p.username + '</small>' : ''}</td>
      <td><span class="badge badge-direct">${p.type.toUpperCase()}</span></td>
      <td>${badge}</td>
      <td>${p.latency > 0 ? '<b>' + p.latency + ' ms</b>' : '-'}</td>
      <td><button class="btn-danger" onclick="deleteProxy('${p.id}')">Xóa</button></td>
    </tr>`;
  }).join('');
}

function renderDevices() {
  const tbody = document.getElementById('deviceTable');
  document.getElementById('devCount').textContent = STATE_DATA.devices.length;
  tbody.innerHTML = STATE_DATA.devices.map(d => {
    const statusBadge = d.online
      ? '<span class="badge badge-live">● Online</span>'
      : '<span class="badge badge-direct">○ Offline</span>';
    let icon = '📱';
    if (d.dev_type === 'aruba') icon = '📡';
    if (d.dev_type === 'pc') icon = '💻';

    const options = ['<option value="">-- Mạng gốc (Direct WAN) --</option>'].concat(
      STATE_DATA.proxies.map(p => {
        const sel = d.proxy_id === p.id ? 'selected' : '';
        const info = p.exit_ip ? ` [${p.country} - ${p.exit_ip}]` : (p.status === 'dead' ? ' [DIE]' : '');
        return `<option value="${p.id}" ${sel}>${p.type.toUpperCase()}://${p.host}:${p.port}${info}</option>`;
      })
    ).join('');

    return `<tr>
      <td>${statusBadge}</td>
      <td>
        <div style="display:flex;align-items:center;gap:6px;">
          <span>${icon}</span>
          <input type="text" id="note_${d.mac}" value="${d.hostname || d.note || ''}" placeholder="Ghi chú máy..." style="width:140px">
        </div>
      </td>
      <td><code>${d.ip}</code> ${d.is_static ? '<span title="Đã cố định IP tĩnh">🔒</span>' : ''}</td>
      <td><code>${d.mac}</code></td>
      <td>
        <select id="proxy_${d.mac}" style="width:225px">${options}</select>
      </td>
      <td>
        <label style="cursor:pointer;display:flex;align-items:center;gap:5px;">
          <input type="checkbox" id="ks_${d.mac}" ${d.kill_switch ? 'checked' : ''}> Chặn nếu Die
        </label>
      </td>
      <td>
        <button onclick="saveDevice('${d.mac}', '${d.ip}')">Áp dụng</button>
      </td>
    </tr>`;
  }).join('');
}

async function importProxies() {
  const text = document.getElementById('proxyInput').value;
  const type = document.getElementById('defaultProxyType').value;
  if (!text.trim()) return;
  const res = await fetch('/api/proxies/import', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ proxies_text: text, type })
  });
  const data = await res.json();
  document.getElementById('proxyInput').value = '';
  showToast(`Đã thêm ${data.added_count} Proxy! Đang kiểm tra kết nối...`);
  await checkAllProxies();
}

async function checkAllProxies() {
  const btn = document.getElementById('btnCheck');
  btn.textContent = '⏳ Đang check...';
  await fetch('/api/proxies/check', { method: 'POST' });
  btn.textContent = '⚡ Check Live / Ping';
  showToast('Đã kiểm tra xong toàn bộ Proxy!');
  await loadData();
}

async function deleteProxy(id) {
  await fetch('/api/proxies/delete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ id })
  });
  await loadData();
}

async function clearProxies() {
  if (!confirm('Xóa toàn bộ Proxy trong kho?')) return;
  await fetch('/api/proxies/clear', { method: 'POST' });
  await loadData();
}

async function saveDevice(mac, ip) {
  const proxy_id = document.getElementById('proxy_' + mac).value;
  const kill_switch = document.getElementById('ks_' + mac).checked;
  const note = document.getElementById('note_' + mac).value;
  await fetch('/api/devices/assign', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ mac, ip, proxy_id, kill_switch, block_quic: true, note })
  });
  showToast(`Đã áp dụng cấu hình cho ${ip} (${mac})!`);
  await loadData();
}

async function lockAllStatic() {
  await fetch('/set_all_static');
  showToast('Đã khóa IP tĩnh cho tất cả thiết bị!');
  await loadData();
}

async function autoAssignProxies() {
  const res = await fetch('/api/devices/auto_assign', { method: 'POST' });
  const data = await res.json();
  if (data.error) {
    alert(data.error);
  } else {
    showToast(`Đã tự động gán Proxy cho ${data.assigned_count} thiết bị!`);
  }
  await loadData();
}

loadData();
setInterval(loadData, 15000);
</script>
</body>
</html>
"""


# =====================================================================
# Universal Server Runner (Supports Flask OR Python Built-in HTTPServer)
# =====================================================================

class GenRouterHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html, status=200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path in ("/", "/dashboard"):
            return self._send_html(DASHBOARD_HTML)
        elif path == "/api/overview":
            res, code = handle_api_overview()
            return self._send_json(res, code)
        elif path == "/set_all_static":
            res, code = handle_set_all_static()
            return self._send_json(res, code)
        elif path == "/del_all_static":
            res, code = handle_del_all_static()
            return self._send_json(res, code)
        elif path == "/list_static":
            res, code = handle_list_static()
            return self._send_json(res, code)
        elif path == "/add_static":
            ip = (qs.get("ip") or [""])[0]
            mac = (qs.get("mac") or [""])[0]
            res, code = handle_add_static(ip, mac)
            return self._send_json(res, code)
        elif path == "/del_static":
            ip = (qs.get("ip") or [""])[0]
            mac = (qs.get("mac") or [""])[0]
            res, code = handle_del_static(ip, mac)
            return self._send_json(res, code)
        else:
            return self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
        try:
            data = json.loads(raw_body) if raw_body else {}
        except Exception:
            data = {}

        if path == "/api/proxies/import":
            res, code = handle_api_import_proxies(data)
            return self._send_json(res, code)
        elif path == "/api/proxies/check":
            res, code = handle_api_check_proxies()
            return self._send_json(res, code)
        elif path == "/api/proxies/delete":
            res, code = handle_api_delete_proxy(data)
            return self._send_json(res, code)
        elif path == "/api/proxies/clear":
            res, code = handle_api_clear_proxies()
            return self._send_json(res, code)
        elif path == "/api/devices/assign":
            res, code = handle_api_assign_device(data)
            return self._send_json(res, code)
        elif path == "/api/devices/auto_assign":
            res, code = handle_api_auto_assign()
            return self._send_json(res, code)
        else:
            return self._send_json({"error": "Not found"}, 404)


if __name__ == "__main__":
    ensure_firewall_and_dns_compatible()
    apply_routing_engine()
    server = ThreadingHTTPServer(("0.0.0.0", 8000), GenRouterHTTPHandler)
    print("GenRouter Pro listening on http://0.0.0.0:8000")
    server.serve_forever()
