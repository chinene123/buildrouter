# ⚡ GenRouter Pro - Hệ Thống Định Tuyến Proxy Tầng Mạng (OpenWrt + Aruba AP)

Hệ thống quản lý và định tuyến Proxy trong suốt (**Transparent Proxy**) theo từng thiết bị (**MAC / IP Address**) dành cho **Mini PC chạy OpenWrt / ImmortalWrt** kết hợp với **Bộ phát Wi-Fi chuyên dụng Aruba (Aruba Instant AP)** phục vụ dàn Box Phone / MMO.

---

## 🏗️ 1. Sơ Đồ Đấu Nối Phần Cứng

```text
[ Modem Nhà Mạng (Viettel/FPT/VNPT) ]
                 │
                 ▼ (Cắm vào cổng WAN - eth0)
     [ MINI PC OPENWRT (172.16.5.1) ]
        ├──► Cổng LAN (eth2) ───► [ Máy Tính Điều Khiển (PC) ]
        │
        └──► Cổng LAN (eth3) ───► [ Bộ Phát Wi-Fi Aruba (Access Point) ]
                                            │
                                            ├── 📱 Điện thoại 1 (IP riêng + Proxy 1)
                                            ├── 📱 Điện thoại 2 (IP riêng + Proxy 2)
                                            └── 📱 Điện thoại N (IP riêng + Proxy N)
```

---

## ✨ 2. Tính Năng Nổi Bật

- **Định tuyến Proxy tầng mạng (Transparent Proxy):**
  - Bọc toàn bộ lưu lượng `TCP` & `UDP` của từng điện thoại đi qua Proxy (`SOCKS5` hoặc `HTTP`) bằng nhân `/usr/bin/gencore` (`sing-box 1.11.6`) + `iptables TPROXY` / `TUN` mà **không cần cài ứng dụng Proxy trên điện thoại**.
- **Chống rò rỉ (Anti-Leak) & Kill-Switch phần cứng:**
  - **DNS Anti-Leak:** Tự động bắt cổng DNS `53` và đẩy truy vấn DNS của từng điện thoại đi xuyên qua đúng Proxy của điện thoại đó.
  - **Chặn QUIC / WebRTC Leak:** Tự động khóa `UDP 443` (QUIC) đối với các thiết bị gắn Proxy để ép trình duyệt/ứng dụng đi qua đường Proxy chuẩn.
  - **Kill-Switch (`nftables forward_killswitch`):** Tự động ngắt kết nối Internet của điện thoại nếu Proxy bị chết (`DIE`), đảm bảo **không bao giờ lộ IP mạng gốc**.
- **Tự động nhận diện Aruba AP & Điện thoại:**
  - Quét trực tiếp bảng DHCP Leases + ARP để hiển thị danh sách thiết bị theo thời gian thực, tự động khóa IP tĩnh (`Static Lease`) theo địa chỉ MAC.
- **Độc lập hoàn toàn (Zero External Dependencies):**
  - Chạy trực tiếp bằng thư viện chuẩn Python3 trên OpenWrt (không bắt buộc cài `Flask` hay `curl` ngoài), tích hợp bộ kiểm tra Proxy (`LIVE/DIE`, `Ping ms`, `GeoIP`, `ISP`) thuần Python.
- **Tương thích ngược 100% API DHCP cũ:**
  - Giữ nguyên các endpoint `/set_all_static`, `/del_all_static`, `/list_static`, `/add_static`, `/del_static` trên cổng `8000`.

---

## 🚀 3. Cách Cài Đặt Cho Các Mini Router Khác

### Cách 1: Cài đặt bằng Giao diện Đồ họa trên Windows (GUI)
1. Cắm dây mạng từ cổng LAN của Mini Router vào máy tính.
2. Nháy đúp chuột vào file **`CaiDat_GenRouter.bat`** (hoặc chạy `python GenRouter_Installer.py`).
3. Nhập **IP của Mini Router** (ví dụ `192.168.1.1` hoặc `172.16.5.1`) và **Mật khẩu SSH**.
4. Bấm nút **🚀 CÀI ĐẶT GENROUTER PRO LÊN MINI ROUTER** và đợi 5–10 giây để hoàn tất.

### Cách 2: Cài đặt bằng Dòng lệnh (CLI)
```powershell
# Cài đặt và giữ nguyên IP LAN hiện tại của Router
python GenRouter_Installer.py --cli --host 172.16.5.1 --password 123123 --no-lan-change

# Cài đặt cho Router OpenWrt mới (IP 192.168.1.1), tự động đổi IP LAN sang 172.16.5.1/20 và đặt pass mới
python GenRouter_Installer.py --cli --host 192.168.1.1 --password "" --new-password 123123 --lan-ip 172.16.5.1
```

---

## 🌐 4. Giao Diện Quản Lý & API

Sau khi cài đặt, mở trình duyệt truy cập:
- **GenRouter Pro Dashboard:** `http://172.16.5.1:8000`
- **LuCI OpenWrt Admin:** `http://172.16.5.1:8880`

### Các API tích hợp sẵn:
| Endpoint | Method | Mô tả |
|---|---|---|
| `/api/overview` | `GET` | Lấy danh sách thiết bị, kho Proxy và trạng thái Engine |
| `/api/proxies/import` | `POST` | Nhập danh sách Proxy hàng loạt (`proxies_text`, `type`) |
| `/api/proxies/check` | `POST` | Kiểm tra Live/Die, Ping (ms), IP đầu ra & Quốc gia |
| `/api/devices/assign` | `POST` | Gán Proxy & bật/tắt Kill-Switch cho từng thiết bị (`mac`, `ip`, `proxy_id`, `kill_switch`) |
| `/api/devices/auto_assign` | `POST` | Tự động gán Proxy 1:1 cho toàn bộ điện thoại |
| `/set_all_static` | `GET` | Cố định IP tĩnh cho toàn bộ DHCP leases hiện tại |
| `/list_static` | `GET` | Xem danh sách các host tĩnh |
| `/add_static?ip=...&mac=...` | `GET` | Thêm thủ công 1 host tĩnh |
| `/del_static?ip=...&mac=...` | `GET` | Xóa host tĩnh theo IP hoặc MAC |

---

## 📂 5. Cấu Trúc Thư Mục

- `GenRouter_Installer.py`: Trình cài đặt tự động (GUI Tkinter & CLI) cho các Mini Router mới.
- `CaiDat_GenRouter.bat`: File chạy nhanh trình cài đặt trên Windows.
- `genrouter_server.py`: Mã nguồn lõi Backend, Engine điều khiển `sing-box`/`iptables`/`nftables` và giao diện Web UI.
- `bin/gencore`: Nhân định tuyến `sing-box 1.11.6 (linux/amd64)` đóng gói sẵn để cài đặt Offline.
- `deploy.py`: Script cập nhật nhanh mã nguồn lên Mini PC `172.16.5.1`.
