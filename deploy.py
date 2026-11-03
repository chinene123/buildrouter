import paramiko
import time
import urllib.request

HOST = "172.16.5.1"
USER = "root"
PASS = "123123"


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=5, allow_agent=False, look_for_keys=False)

    # Backup original app.py if not backed up yet
    c.exec_command("cp -n /etc/shm/app.py /etc/shm/app.py.bak 2>/dev/null || true; mkdir -p /etc/genrouter")
    time.sleep(0.5)

    sftp = c.open_sftp()
    sftp.put(r"d:\buildrouter\genrouter_server.py", "/etc/shm/app.py")
    sftp.put(r"d:\buildrouter\genrouter_server.py", "/etc/genrouter/genrouter_server.py")
    sftp.close()

    # Restart sdhcp and check running processes
    cmd = (
        "/etc/init.d/sdhcp stop; "
        "killall -9 python3 2>/dev/null || true; "
        "/etc/init.d/sdhcp start; "
        "sleep 2; "
        "ps w | grep -E 'app.py|gencore'; "
        "echo '=== NFT TABLE ==='; "
        "nft list table ip genrouter"
    )
    stdin, stdout, stderr = c.exec_command(cmd)
    print(stdout.read().decode("utf-8", errors="replace"))
    err = stderr.read().decode("utf-8", errors="replace")
    if err:
        print("STDERR:", err)
    c.close()

    time.sleep(1)
    with urllib.request.urlopen("http://172.16.5.1:8000/api/overview", timeout=5) as resp:
        print("=== /api/overview ===")
        print(resp.read().decode("utf-8"))


if __name__ == "__main__":
    main()
