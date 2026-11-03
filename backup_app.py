import os
import subprocess
import re
import ipaddress
from flask import Flask, request, jsonify
from urllib.parse import urlencode
import json

app = Flask(__name__)

from flask import Flask, request, url_for

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    """
    Trang chủ: hiển thị HTML liệt kê các endpoint và hướng dẫn sử dụng.
    """
    routes = [
        {
            "endpoint": url_for('index'),
            "method": "GET",
            "description": "Trang chủ, liệt kê các API và cách dùng."
        },
        {
            "endpoint": url_for('set_all_static'),
            "method": "GET",
            "description": "Tự động thêm tất cả DHCP leases mới thành host tĩnh."
        },
        {
            "endpoint": url_for('del_all_static'),
            "method": "GET",
            "description": "Xóa toàn bộ các host tĩnh khỏi config DHCP."
        },
        {
            "endpoint": url_for('list_static'),
            "method": "GET",
            "description": "Hiển thị danh sách tất cả các host tĩnh."
        },
        {
            "endpoint": url_for('add_static'),
            "method": "GET",
            "description": (
                "Thêm thủ công 1 host tĩnh. "
                "Tham số query: <code>?ip=IP_ADDRESS&amp;mac=MAC_ADDRESS</code><br>"
                "Ví dụ: <code>/add_static?ip=192.168.5.123&amp;mac=AA:BB:CC:DD:EE:FF</code>"
            )
        },
        {
            "endpoint": url_for('del_static'),
            "method": "GET",
            "description": (
                "Xóa một host tĩnh dựa trên IP hoặc MAC. "
                "Tham số query: <code>?ip=IP_ADDRESS</code> hoặc "
                "<code>?mac=MAC_ADDRESS</code><br>"
                "Ví dụ: <code>/del_static?ip=192.168.5.50</code> hoặc "
                "<code>/del_static?mac=AA:BB:CC:DD:EE:FF</code>"
            )
        }
    ]

    # Xây dựng HTML
    html = ['<!DOCTYPE html>',
            '<html><head>',
            '  <meta charset="utf-8">',
            '  <title>Flask DHCP API Documentation</title>',
            '  <style>',
            '    body { font-family: Arial, sans-serif; padding: 20px; }',
            '    table { border-collapse: collapse; width: 100%; }',
            '    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }',
            '    th { background-color: #f2f2f2; }',
            '    code { background-color: #eee; padding: 2px 4px; }',
            '  </style>',
            '</head><body>',
            '  <h1>API Documentation</h1>',
            '  <table>',
            '    <tr><th>Endpoint</th><th>Method</th><th>Description</th></tr>']

    for r in routes:
        html.append(f"    <tr>"
                    f"<td><a href=\"{r['endpoint']}\">{r['endpoint']}</a></td>"
                    f"<td>{r['method']}</td>"
                    f"<td>{r['description']}</td>"
                    f"</tr>")

    html.extend([
        '  </table>',
        '</body></html>'
    ])

    return '\n'.join(html), 200, {'Content-Type': 'text/html'}

# Ví dụ endpoint nhận JSON POST
@app.route('/api/data', methods=['POST'])
def api_data():
    data = request.get_json(silent=True) or {}
    response = {'status': 'ok', 'received': data}
    return jsonify(response)

# Ví dụ URL-encode
@app.route('/encode', methods=['GET'])
def encode_example():
    params = {'foo': 'bar baz', 'num': 123}
    qs = urlencode(params)
    return f"Encoded query string: {qs}"

# Thực thi lệnh hệ thống

def send_command(command):
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout if result.stdout else result.stderr

def send_command_ver2(command):
    os.system(f'{command} 2>&1')

# Lấy danh sách DHCP leases

def get_list_dhcp():
    raw = send_command("ubus call luci-rpc getDHCPLeases")
    return json.loads(raw)

# Các hàm hỗ trợ UCI

def uci_set(config, name, settings):
    for key, value in settings.items():
        if key in ['interface', 'service']:
            os.system(f"uci set {config}.{name}={key} 2>&1")
        else:
            os.system(f"uci set {config}.{name}.{key}='{value}' 2>&1")

def uci_add(config):
    os.system(f"uci add {config} 2>&1")

def uci_commit(config):
    os.system(f"uci commit {config} 2>&1")

def uci_del(config, name=None, settings=None):
    if settings:
        for section in settings:
            os.system(f"uci delete {config}.{section} >/dev/null 2>&1")
    elif name:
        os.system(f"uci delete {config}.{name} >/dev/null 2>&1")

def get_existing_static():
    # gọi UCI để lấy toàn bộ dhcp config
    raw = send_command(f"ubus call uci get '{json.dumps({'config': 'dhcp'})}'")
    uci_data = json.loads(raw)
    values = uci_data.get('values', {})

    existing_ips = set()
    existing_macs = set()
    for sec in values.values():
        if sec.get('.type') == 'host':
            ip = sec.get('ip')
            mac = sec.get('mac')
            if ip:  existing_ips.add(ip)
            if mac: existing_macs.add(mac)
    return existing_ips, existing_macs

def save_static():
    """
    Lấy toàn bộ các host tĩnh (section .type == 'host') từ UCI DHCP
    và lưu vào file list_ip_static.json trong thư mục dự án.
    Trả về dict các hosts vừa lưu.
    """
    # 1. Gọi UBUS để lấy config dhcp
    raw = send_command(
        f"ubus call uci get '{json.dumps({'config': 'dhcp'})}'"
    )
    try:
        uci_data = json.loads(raw)
    except ValueError:
        raise RuntimeError(f"Invalid JSON from UBUS: {raw}")

    # 2. Lọc ra các section .type == 'host'
    values = uci_data.get('values', {})
    hosts = {}
    for section, sec in values.items():
        if sec.get('.type') == 'host':
            hosts[section] = sec

    # 3. Ghi ra file JSON
    json_path = os.path.join(
        os.path.dirname(__file__),
        'list_ip_static.json'
    )
    with open(json_path, 'w') as jf:
        json.dump(hosts, jf, indent=4)

    return hosts

@app.route('/set_all_static', methods=['GET'])
def set_all_static():
    dhcp_data = get_list_dhcp()
    leases = dhcp_data.get('dhcp_leases', [])

    existing_ips, existing_macs = get_existing_static()
    static_entries = []

    for lease in leases:
        hostname = lease.get('hostname')
        ipaddr   = lease.get('ipaddr')
        macaddr  = lease.get('macaddr')

        # nếu IP hoặc MAC đã có trong existing, bỏ qua
        if ipaddr in existing_ips or macaddr in existing_macs:
            continue

        # thêm host tĩnh mới
        os.system("uci add dhcp host >/dev/null 2>&1")
        settings = {
            "name": hostname,
            "ip":   ipaddr,
            "mac":  macaddr
        }
        uci_set('dhcp', '@host[-1]', settings)
        uci_commit('dhcp')

        # ghi lại để trả về và lưu file
        static_entries.append({
            "hostname": hostname,
            "ip":       ipaddr,
            "mac":      macaddr
        })
        existing_ips.add(ipaddr)
        existing_macs.add(macaddr)

    # ghi file JSON trong project
    if len(static_entries) > 0:
        os.system("/etc/init.d/odhcpd reload >/dev/null 2>&1")
    save_static()
    return jsonify({
        "static_hosts_added": static_entries,
    })

@app.route('/del_all_static', methods=['GET'])
def del_all_static():
    # 1. Lấy toàn bộ config dhcp qua UBUS
    raw = send_command(f"ubus call uci get '{json.dumps({'config': 'dhcp'})}'")
    uci_data = json.loads(raw)
    values = uci_data.get('values', {})

    deleted = []
    # 2. Duyệt qua mỗi section, nếu .type == 'host' thì xóa
    for section, sec in values.items():
        if sec.get('.type') == 'host':
            deleted.append({
                "section":  section,
                "hostname": sec.get('name'),
                "ip":       sec.get('ip'),
                "mac":      sec.get('mac')
            })
            # Xóa section host này
            uci_del('dhcp', name=section)
    # ghi file JSON trong project
    
    # 3. Commit 1 lần sau khi đã xóa hết
    if deleted:
        os.system("uci commit dhcp >/dev/null 2>&1")
        os.system("/etc/init.d/odhcpd reload >/dev/null 2>&1")
    save_static()
    # 4. Trả về kết quả
    return jsonify({
        "deleted_hosts": deleted
    })

@app.route('/list_static', methods=['GET'])
def list_static():
    # 1. Gọi UBUS để lấy toàn bộ config dhcp
    raw = send_command(f"ubus call uci get '{json.dumps({'config': 'dhcp'})}'")
    try:
        uci_data = json.loads(raw)
    except ValueError:
        return jsonify({
            "error": "Invalid JSON from UBUS",
            "raw": raw
        }), 500

    # 2. Lấy ra các section .type == 'host'
    values = uci_data.get('values', {})
    hosts = {}
    for section, sec in values.items():
        if sec.get('.type') == 'host':
            hosts[section] = sec

    # 3. Trả về JSON chỉ gồm các host static
    return jsonify(hosts)
@app.route('/add_static', methods=['GET'])
def add_static():
    # 1. Lấy params
    ip = request.args.get('ip')
    mac = request.args.get('mac')
    if not ip or not mac:
        return jsonify(error="Missing 'ip' or 'mac' query parameter"), 400

    # 2. Validate IPv4
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return jsonify(error=f"Invalid IPv4 address: {ip}"), 400

    # 3. Validate MAC (6 cặp hex, phân tách bằng :)
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
    if not mac_pattern.match(mac):
        return jsonify(error=f"Invalid MAC address: {mac}"), 400

    # 4. Thêm host tĩnh qua UCI
    # Tạo section mới
    os.system("uci add dhcp host >/dev/null 2>&1")

    # Đặt tên section, dùng MAC không dấu để tránh ký tự lạ
    section_name = f"static_{mac.replace(':','')}"
    settings = {
        "name": section_name,
        "ip":   ip,
        "mac":  mac
    }
    uci_set('dhcp', '@host[-1]', settings)
    os.system("uci commit dhcp >/dev/null 2>&1")

    # 5. Reload dịch vụ DHCP nếu cần
    os.system("/etc/init.d/odhcpd reload >/dev/null 2>&1")
    save_static()
    # 6. Trả về kết quả
    return jsonify({
        "status":  "success",
        "section": section_name,
        "ip":      ip,
        "mac":     mac
    }), 201

@app.route('/del_static', methods=['GET'])
def del_static():
    """
    Xóa một host tĩnh dựa trên IP hoặc MAC.
    Tham số query:
      - ip: địa chỉ IPv4 cần xóa
      - mac: địa chỉ MAC cần xóa
    Ví dụ: /del_static?ip=192.168.5.50
           /del_static?mac=AA:BB:CC:DD:EE:FF
    """
    ip = request.args.get('ip')
    mac = request.args.get('mac')
    if not ip and not mac:
        return jsonify(error="Thiếu tham số 'ip' hoặc 'mac'"), 400

    # 1. Lấy toàn bộ config DHCP qua UBUS
    raw = send_command(f"ubus call uci get '{json.dumps({'config': 'dhcp'})}'")
    try:
        uci_data = json.loads(raw)
    except ValueError:
        return jsonify(error="Invalid JSON from UBUS", raw=raw), 500

    values = uci_data.get('values', {})
    to_delete = []

    # 2. Tìm các section phù hợp
    for section, sec in values.items():
        if sec.get('.type') != 'host':
            continue
        if (ip and sec.get('ip') == ip) or (mac and sec.get('mac') == mac):
            to_delete.append({
                "section": section,
                "hostname": sec.get('name'),
                "ip": sec.get('ip'),
                "mac": sec.get('mac')
            })

    if not to_delete:
        return jsonify(message="Không tìm thấy host tĩnh tương ứng"), 404

    # 3. Xóa các section đã tìm được
    for item in to_delete:
        uci_del('dhcp', name=item['section'])

    # 4. Commit và reload
    os.system("uci commit dhcp >/dev/null 2>&1")
    os.system("/etc/init.d/odhcpd reload >/dev/null 2>&1")
    save_static()
    return jsonify(deleted=to_delete), 200
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)
