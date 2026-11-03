#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GenRouter Pro - Trình Cài Đặt Tự Động Cho Các Mini Router (OpenWrt / ImmortalWrt / Linux)
Hỗ trợ cả Giao diện Đồ họa (GUI) trên Windows và Dòng lệnh (CLI).
"""

import argparse
import os
import re
import socket
import subprocess
import sys
import threading
import time
import webbrowser

try:
    import paramiko
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko"])
    import paramiko

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_SCRIPT_PATH = os.path.join(BASE_DIR, "genrouter_server.py")
LOCAL_GENCORE_PATH = os.path.join(BASE_DIR, "bin", "gencore")

SDHCP_INIT_SCRIPT = """#!/bin/sh /etc/rc.common
START=90
STOP=10
USE_PROCD=1

APP_BIN=/usr/bin/python3
APP_SCRIPT=/etc/shm/app.py
APP_USER=root

start_service() {
    procd_open_instance
    procd_set_param user    $APP_USER
    procd_set_param command $APP_BIN $APP_SCRIPT
    procd_set_param stdout  1
    procd_set_param stderr  1
    procd_set_param respawn
    procd_close_instance
}
"""


def detect_connected_gateways():
    """Find default gateways on Windows interfaces to auto-discover connected Mini Routers."""
    gateways = []
    try:
        out = subprocess.check_output("ipconfig", shell=True, text=True, errors="ignore")
        for m in re.finditer(r"Default Gateway[ .\s]*:\s*(\d+\.\d+\.\d+\.\d+)", out):
            gw = m.group(1)
            if gw not in gateways:
                gateways.append(gw)
    except Exception:
        pass
    for candidate in ("172.16.5.1", "192.168.1.1", "192.168.2.1", "192.168.10.1"):
        if candidate not in gateways:
            gateways.append(candidate)
    return gateways


def ssh_connect(host, port, user, password, timeout=6):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=int(port),
            username=user,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        return client
    except paramiko.AuthenticationException:
        # Handle OpenWrt fresh install with empty password ("none" auth)
        if not password:
            transport = client.get_transport()
            if transport and transport.is_active():
                transport.auth_none(user)
                return client
        raise


def ssh_run(client, cmd, timeout=60):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    code = stdout.channel.recv_exit_status()
    return code, out, err


def run_installation(
    host,
    port=22,
    user="root",
    password="",
    new_password="",
    configure_lan=True,
    new_lan_ip="172.16.5.1",
    new_lan_mask="255.255.240.0",
    install_gencore=True,
    log_fn=print,
    progress_fn=None,
):
    def set_prog(val):
        if progress_fn:
            progress_fn(val)

    set_prog(5)
    log_fn(f"🔌 [1/7] Đang kết nối SSH tới Mini Router {user}@{host}:{port}...")
    client = ssh_connect(host, port, user, password)

    code, sys_info, _ = ssh_run(client, "uname -a; cat /etc/openwrt_release 2>/dev/null || true")
    arch_code, arch, _ = ssh_run(client, "uname -m")
    log_fn(f"✅ Đã kết nối thành công! Kiến trúc CPU: {arch}")
    for line in sys_info.splitlines()[:3]:
        log_fn(f"   ℹ️ {line}")

    # Step 2: Remount RW & Remove old MAC locks
    set_prog(18)
    log_fn("🔓 [2/7] Mở khóa ghi ổ đĩa (Read-Write) & xóa các script khóa MAC cũ...")
    ssh_run(client, "mount -o remount,rw / 2>/dev/null || true")
    ssh_run(
        client,
        "rm -f /etc/init.d/check_mac /etc/rc.d/*check_mac* /etc/rc.d/*genrouter* 2>/dev/null || true; "
        "mkdir -p /etc/genrouter /etc/shm"
    )

    # Optional: Change root password
    if new_password.strip():
        npw = new_password.strip()
        log_fn(f"🔑 Đang cập nhật mật khẩu root mới trên Router...")
        ssh_run(client, f"echo -e '{npw}\\n{npw}' | passwd root >/dev/null 2>&1 || true")

    # Step 3: Check & Install Python3 / TPROXY / TUN packages if missing
    set_prog(32)
    log_fn("📦 [3/7] Kiểm tra môi trường Python3 & gói tường lửa (nftables / iptables TPROXY)...")
    code_py, py_path, _ = ssh_run(client, "which python3")
    if code_py != 0 or not py_path:
        log_fn("   ⏳ Chưa có python3, đang tự động tải và cài đặt python3-light qua opkg...")
        ssh_run(client, "opkg update && opkg install python3-light python3-urllib python3-logging python3-openssl", timeout=180)
    else:
        log_fn(f"   ✅ Đã có sẵn Python3 ({py_path})")

    # Try installing TPROXY / TUN helpers if missing (non-fatal if offline)
    code_tp, _, _ = ssh_run(client, "lsmod | grep -iE 'xt_TPROXY|tun'")
    if code_tp != 0:
        log_fn("   ⏳ Đang kiểm tra/cài đặt module kmod-ipt-tproxy, iptables-mod-tproxy, kmod-tun...")
        ssh_run(client, "opkg update && opkg install iptables-nft iptables-mod-tproxy kmod-ipt-tproxy kmod-tun 2>/dev/null || true", timeout=120)

    # Step 4: Upload gencore (sing-box) binary
    set_prog(52)
    if install_gencore:
        log_fn("🚀 [4/7] Kiểm tra và cài đặt nhân định tuyến Proxy (/usr/bin/gencore - sing-box)...")
        code_gc, gc_ver, _ = ssh_run(client, "/usr/bin/gencore version 2>/dev/null | head -n 1")
        if code_gc == 0 and "sing-box" in gc_ver:
            log_fn(f"   ✅ Trên Router đã có sẵn gencore: {gc_ver}")
        elif arch == "x86_64" and os.path.exists(LOCAL_GENCORE_PATH):
            size_mb = os.path.getsize(LOCAL_GENCORE_PATH) / (1024 * 1024)
            log_fn(f"   📤 Đang tải nhân gencore ({size_mb:.1f} MB) từ máy tính lên /usr/bin/gencore...")
            ssh_run(client, "killall -9 gencore sing-box 2>/dev/null || true")
            sftp = client.open_sftp()
            sftp.put(LOCAL_GENCORE_PATH, "/usr/bin/gencore")
            sftp.close()
            ssh_run(client, "chmod +x /usr/bin/gencore")
            log_fn("   ✅ Đã cài đặt xong /usr/bin/gencore (sing-box 1.11.6)!")
        else:
            log_fn(f"   ⏳ Đang cài đặt sing-box cho kiến trúc {arch} qua opkg...")
            ssh_run(client, "opkg update && opkg install sing-box && ln -sf /usr/bin/sing-box /usr/bin/gencore", timeout=120)

    # Step 5: Upload GenRouter Pro Server & Init Script
    set_prog(72)
    log_fn("📄 [5/7] Đang nạp mã nguồn GenRouter Pro Server & Web Dashboard lên Router...")
    if not os.path.exists(SERVER_SCRIPT_PATH):
        raise FileNotFoundError(f"Không tìm thấy file {SERVER_SCRIPT_PATH}")

    sftp = client.open_sftp()
    sftp.put(SERVER_SCRIPT_PATH, "/etc/shm/app.py")
    sftp.put(SERVER_SCRIPT_PATH, "/etc/genrouter/genrouter_server.py")
    with sftp.open("/etc/init.d/sdhcp", "w") as f:
        f.write(SDHCP_INIT_SCRIPT.replace("\r\n", "\n"))
    sftp.close()

    ssh_run(client, "chmod +x /etc/shm/app.py /etc/genrouter/genrouter_server.py /etc/init.d/sdhcp")
    ssh_run(client, "/etc/init.d/sdhcp enable")

    # Step 6: Configure DNS, Firewall & Optional LAN IP/DHCP Pool
    set_prog(85)
    log_fn("⚙️ [6/7] Cấu hình DNS Anti-Leak (port 5353/53), Tường lửa & DHCP Aruba...")
    dns_fw_cmd = (
        "grep -q 'port=5353' /etc/dnsmasq.conf 2>/dev/null || echo 'port=5353' >> /etc/dnsmasq.conf; "
        "uci set dhcp.@dnsmasq[0].dns_redirect='1'; "
        "uci set dhcp.lan.start='10'; "
        "uci set dhcp.lan.limit='1000'; "
        "uci set dhcp.lan.leasetime='30d'; "
        "uci commit dhcp; "
        "uci set firewall.@defaults[0].flow_offloading='0'; "
        "uci set firewall.@defaults[0].flow_offloading_hw='0'; "
        "uci commit firewall; "
        "/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true; "
        "/etc/init.d/firewall reload >/dev/null 2>&1 || true"
    )
    ssh_run(client, dns_fw_cmd)

    # Step 7: Start GenRouter Pro Service
    set_prog(95)
    log_fn("🔥 [7/7] Khởi động dịch vụ GenRouter Pro và kiểm tra trạng thái...")
    ssh_run(
        client,
        "/etc/init.d/sdhcp stop >/dev/null 2>&1 || true; "
        "killall -9 python3 2>/dev/null || true; "
        "/etc/init.d/sdhcp start; "
        "sleep 2"
    )
    _, ps_out, _ = ssh_run(client, "ps w | grep -E 'app.py|gencore' | grep -v grep")
    log_fn("   📊 Tiến trình đang chạy:")
    for line in ps_out.splitlines():
        log_fn(f"      {line}")

    target_ip = host
    if configure_lan and new_lan_ip.strip() and new_lan_ip.strip() != host:
        target_ip = new_lan_ip.strip()
        log_fn(f"🌐 Đang đổi IP LAN của Router sang {target_ip} (Netmask {new_lan_mask})...")
        lan_cmd = (
            f"uci set network.lan.ipaddr='{target_ip}'; "
            f"uci set network.lan.netmask='{new_lan_mask}'; "
            f"uci del dhcp.lan.dhcp_option 2>/dev/null || true; "
            f"uci add_list dhcp.lan.dhcp_option='6,{target_ip}'; "
            f"uci commit network; uci commit dhcp; "
            f"nohup sh -c 'sleep 1; /etc/init.d/network restart; /etc/init.d/dnsmasq restart' >/dev/null 2>&1 &"
        )
        ssh_run(client, lan_cmd)

    client.close()
    set_prog(100)
    log_fn("=" * 62)
    log_fn(f"🎉 HOÀN TẤT CÀI ĐẶT GENROUTER PRO TRÊN MINI ROUTER!")
    log_fn(f"👉 Địa chỉ Web Quản Lý: http://{target_ip}:8000")
    log_fn("=" * 62)
    return target_ip


# =====================================================================
# Giao Diện Đồ Họa (Tkinter GUI) Trên Windows
# =====================================================================

def launch_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext

    root = tk.Tk()
    root.title("GenRouter Pro Installer - Cài đặt tự động cho Mini Router (OpenWrt)")
    root.geometry("760x660")
    root.configure(bg="#0f172a")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TFrame", background="#0f172a")
    style.configure("Card.TFrame", background="#1e293b")
    style.configure("TLabel", background="#1e293b", foreground="#f8fafc", font=("Segoe UI", 10))
    style.configure("Header.TLabel", background="#0f172a", foreground="#38bdf8", font=("Segoe UI", 15, "bold"))
    style.configure("Sub.TLabel", background="#0f172a", foreground="#94a3b8", font=("Segoe UI", 9))
    style.configure("TCheckbutton", background="#1e293b", foreground="#f8fafc", font=("Segoe UI", 10))

    # Header
    hdr = ttk.Frame(root)
    hdr.pack(fill="x", padx=20, pady=(15, 8))
    ttk.Label(hdr, text="⚡ Trình Cài Đặt GenRouter Pro Cho Mini PC / OpenWrt", style="Header.TLabel").pack(anchor="w")
    ttk.Label(
        hdr,
        text="Tự động nạp nhân định tuyến Proxy (Sing-box TPROXY/TUN), chống DNS/WebRTC Leak, Kill-Switch & Web UI",
        style="Sub.TLabel",
    ).pack(anchor="w")

    # Connection Card
    card1 = ttk.Frame(root, style="Card.TFrame", padding=15)
    card1.pack(fill="x", padx=20, pady=6)

    gateways = detect_connected_gateways()
    default_ip = gateways[0] if gateways else "172.16.5.1"

    ttk.Label(card1, text="1. Thông tin kết nối SSH tới Mini Router:", font=("Segoe UI", 10, "bold")).grid(
        row=0, column=0, columnspan=4, sticky="w", pady=(0, 8)
    )

    ttk.Label(card1, text="IP Mini Router:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
    ip_var = tk.StringVar(value=default_ip)
    ip_combo = ttk.Combobox(card1, textvariable=ip_var, values=gateways, width=18, font=("Segoe UI", 10))
    ip_combo.grid(row=1, column=1, sticky="w", pady=4)

    ttk.Label(card1, text="Cổng SSH:").grid(row=1, column=2, sticky="w", padx=(18, 8), pady=4)
    port_var = tk.StringVar(value="22")
    ttk.Entry(card1, textvariable=port_var, width=8, font=("Segoe UI", 10)).grid(row=1, column=3, sticky="w", pady=4)

    ttk.Label(card1, text="Tài khoản:").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
    user_var = tk.StringVar(value="root")
    ttk.Entry(card1, textvariable=user_var, width=20, font=("Segoe UI", 10)).grid(row=2, column=1, sticky="w", pady=4)

    ttk.Label(card1, text="Mật khẩu SSH:").grid(row=2, column=2, sticky="w", padx=(18, 8), pady=4)
    pass_var = tk.StringVar(value="123123")
    ttk.Entry(card1, textvariable=pass_var, width=22, font=("Segoe UI", 10)).grid(row=2, column=3, sticky="w", pady=4)

    # Options Card
    card2 = ttk.Frame(root, style="Card.TFrame", padding=15)
    card2.pack(fill="x", padx=20, pady=6)

    ttk.Label(card2, text="2. Tùy chọn cấu hình cho Mini Router mới:", font=("Segoe UI", 10, "bold")).grid(
        row=0, column=0, columnspan=4, sticky="w", pady=(0, 8)
    )

    cfg_lan_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        card2,
        text="Cấu hình dải IP LAN chuẩn Aruba / Box Phone (1000 IP, Lease 30 ngày):",
        variable=cfg_lan_var,
    ).grid(row=1, column=0, columnspan=2, sticky="w", pady=4)

    lan_ip_var = tk.StringVar(value="172.16.5.1")
    ttk.Entry(card2, textvariable=lan_ip_var, width=15, font=("Segoe UI", 10)).grid(row=1, column=2, sticky="w", padx=6, pady=4)

    inst_gc_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        card2,
        text="Nạp nhân định tuyến /usr/bin/gencore (Sing-box 1.11.6) từ bộ cài máy tính",
        variable=inst_gc_var,
    ).grid(row=2, column=0, columnspan=3, sticky="w", pady=4)

    ttk.Label(card2, text="Đổi mật khẩu root mới (để trống nếu giữ nguyên):").grid(
        row=3, column=0, columnspan=2, sticky="w", pady=4
    )
    new_pass_var = tk.StringVar(value="")
    ttk.Entry(card2, textvariable=new_pass_var, width=15, font=("Segoe UI", 10)).grid(
        row=3, column=2, sticky="w", padx=6, pady=4
    )

    # Action Buttons & Progress
    btn_frame = ttk.Frame(root)
    btn_frame.pack(fill="x", padx=20, pady=8)

    progress = ttk.Progressbar(root, orient="horizontal", mode="determinate", maximum=100)
    progress.pack(fill="x", padx=20, pady=(0, 8))

    log_box = scrolledtext.ScrolledText(
        root, height=14, bg="#090d16", fg="#34d399", font=("Consolas", 10), insertbackground="#fff"
    )
    log_box.pack(fill="both", expand=True, padx=20, pady=(0, 15))

    def append_log(msg):
        def _do():
            log_box.insert("end", msg + "\n")
            log_box.see("end")
        root.after(0, _do)

    def set_progress(val):
        root.after(0, lambda: progress.configure(value=val))

    def on_test_ssh():
        def _worker():
            host = ip_var.get().strip()
            port = port_var.get().strip() or "22"
            user = user_var.get().strip() or "root"
            pw = pass_var.get()
            append_log(f"🔍 Đang kiểm tra kết nối SSH tới {user}@{host}:{port}...")
            try:
                c = ssh_connect(host, port, user, pw, timeout=5)
                _, info, _ = ssh_run(c, "uname -a; df -h /")
                c.close()
                append_log("✅ KẾT NỐI SSH THÀNH CÔNG!\n" + info + "\n" + "-" * 50)
            except Exception as e:
                append_log(f"❌ Lỗi kết nối SSH: {e}")
        threading.Thread(target=_worker, daemon=True).start()

    def on_install():
        btn_install.configure(state="disabled")
        def _worker():
            try:
                final_ip = run_installation(
                    host=ip_var.get().strip(),
                    port=int(port_var.get().strip() or 22),
                    user=user_var.get().strip() or "root",
                    password=pass_var.get(),
                    new_password=new_pass_var.get(),
                    configure_lan=cfg_lan_var.get(),
                    new_lan_ip=lan_ip_var.get().strip(),
                    install_gencore=inst_gc_var.get(),
                    log_fn=append_log,
                    progress_fn=set_progress,
                )
                root.after(0, lambda: messagebox.showinfo(
                    "Cài đặt thành công!",
                    f"Đã cài đặt hoàn tất GenRouter Pro lên Mini Router!\n\nMở trình duyệt tại: http://{final_ip}:8000"
                ))
            except Exception as e:
                append_log(f"❌ LỖI CÀI ĐẶT: {e}")
                root.after(0, lambda: messagebox.showerror("Lỗi cài đặt", str(e)))
            finally:
                root.after(0, lambda: btn_install.configure(state="normal"))

        threading.Thread(target=_worker, daemon=True).start()

    def on_open_web():
        target = lan_ip_var.get().strip() if cfg_lan_var.get() else ip_var.get().strip()
        webbrowser.open(f"http://{target}:8000")

    btn_test = tk.Button(
        btn_frame, text="🔌 Kiểm tra kết nối SSH", command=on_test_ssh,
        bg="#334155", fg="#fff", font=("Segoe UI", 10, "bold"), relief="flat", padx=14, pady=7, cursor="hand2"
    )
    btn_test.pack(side="left", padx=(0, 10))

    btn_install = tk.Button(
        btn_frame, text="🚀 CÀI ĐẶT GENROUTER PRO LÊN MINI ROUTER", command=on_install,
        bg="#2563eb", fg="#fff", font=("Segoe UI", 10, "bold"), relief="flat", padx=18, pady=7, cursor="hand2"
    )
    btn_install.pack(side="left", padx=(0, 10))

    btn_web = tk.Button(
        btn_frame, text="🌐 Mở Web Dashboard", command=on_open_web,
        bg="#10b981", fg="#fff", font=("Segoe UI", 10, "bold"), relief="flat", padx=14, pady=7, cursor="hand2"
    )
    btn_web.pack(side="right")

    append_log("✨ Sẵn sàng! Hãy nhập IP và mật khẩu SSH của Mini Router rồi bấm 'CÀI ĐẶT GENROUTER PRO'.")
    if os.path.exists(LOCAL_GENCORE_PATH):
        sz = os.path.getsize(LOCAL_GENCORE_PATH) / (1024 * 1024)
        append_log(f"📦 Đã tìm thấy bộ cài Offline '/usr/bin/gencore' ({sz:.1f} MB) trong thư mục bin/gencore.")

    root.mainloop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GenRouter Pro Installer for OpenWrt Mini Routers")
    parser.add_argument("--cli", action="store_true", help="Chạy ở chế độ dòng lệnh (không mở GUI)")
    parser.add_argument("--host", default="172.16.5.1", help="Địa chỉ IP của Mini Router")
    parser.add_argument("--port", type=int, default=22, help="Cổng SSH (mặc định: 22)")
    parser.add_argument("--user", default="root", help="Tài khoản SSH (mặc định: root)")
    parser.add_argument("--password", default="123123", help="Mật khẩu SSH hiện tại")
    parser.add_argument("--new-password", default="", help="Đổi mật khẩu root mới trên Router")
    parser.add_argument("--lan-ip", default="172.16.5.1", help="IP LAN muốn đặt cho Router")
    parser.add_argument("--no-lan-change", action="store_true", help="Giữ nguyên cấu hình IP LAN hiện tại")
    args = parser.parse_args()

    if args.cli:
        run_installation(
            host=args.host,
            port=args.port,
            user=args.user,
            password=args.password,
            new_password=args.new_password,
            configure_lan=not args.no_lan_change,
            new_lan_ip=args.lan_ip,
        )
    else:
        launch_gui()
