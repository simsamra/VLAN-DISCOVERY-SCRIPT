
import csv
import ipaddress
import re
import sys
from getpass import getpass
from datetime import datetime
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from netmiko import ConnectHandler

SWITCHES_FILE = "switches.txt"
DEVICE_TYPE = "cisco_ios"

SHOW_VLAN_CMDS = ["show vlan brief", "show vlan"]
VLAN_LINE_RE = re.compile(r"^\s*(\d{1,4})\s+([A-Za-z0-9_\-\.]+)")

def read_switch_ips(path: str) -> list[str]:
    ips = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ip = line.split(",")[0].split()[0]
            ips.append(ip)
    return ips

def ip_in_subnet(ip: str, subnet: ipaddress._BaseNetwork) -> bool:
    try:
        return ipaddress.ip_address(ip) in subnet
    except ValueError:
        return False

def run_show_vlan(conn) -> str:
    for cmd in SHOW_VLAN_CMDS:
        try:
            out = conn.send_command(cmd, expect_string=r"#|>|\$|\)")
            if out and "Invalid input" not in out and "Unknown command" not in out:
                return out
        except Exception:
            continue
    raise RuntimeError("Unable to run a VLAN show command on this device.")

def parse_vlans(output: str) -> dict[str, str]:
    vlans = {}
    for line in output.splitlines():
        m = VLAN_LINE_RE.match(line)
        if not m:
            continue
        vid, vname = m.group(1), m.group(2)
        try:
            vid_int = int(vid)
            if not (1 <= vid_int <= 4094):
                continue
        except ValueError:
            continue
        vlans[str(vid_int)] = vname
    return vlans

def collect_switch_vlans(ip: str, username: str, password: str, secret: str | None = None, timeout: int = 15) -> dict[str, str]:
    """Try to connect and return VLANs. Raise on failure so caller can skip."""
    device = {
        "device_type": DEVICE_TYPE,
        "host": ip,
        "username": username,
        "password": password,
        "conn_timeout": timeout,
        "timeout": timeout,
    }
    if secret:
        device["secret"] = secret

    conn = None
    try:
        conn = ConnectHandler(**device)
        if secret:
            try:
                conn.enable()
            except Exception:
                pass
        out = run_show_vlan(conn)
        return parse_vlans(out)
    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass

def main():
    # subnet prompt
    try:
        subnet_str = input("Enter subnet in CIDR (e.g., 10.10.0.0/24): ").strip()
        subnet = ipaddress.ip_network(subnet_str, strict=False)
    except Exception:
        print("Invalid subnet. Example: 10.10.0.0/24")
        sys.exit(1)

    try:
        all_ips = read_switch_ips(SWITCHES_FILE)
    except FileNotFoundError:
        print(f"Missing {SWITCHES_FILE}.")
        sys.exit(1)

    target_ips = [ip for ip in all_ips if ip_in_subnet(ip, subnet)]
    if not target_ips:
        print(f"No switches found inside {subnet}.")
        sys.exit(0)

    print(f"Checking {len(target_ips)} switches in {subnet} ...")

    username = input("Username: ").strip()
    password = getpass("Password: ")
    enable_secret = None  # Optional: getpass("Enable secret (or Enter if none): ").strip() or None

    per_switch_vlans = {}
    failed = {}

    with ThreadPoolExecutor(max_workers=min(16, len(target_ips))) as pool:
        futures = {pool.submit(collect_switch_vlans, ip, username, password, enable_secret): ip for ip in target_ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                vlans = fut.result()
                per_switch_vlans[ip] = vlans
                print(f"[OK] {ip}: {len(vlans)} VLANs")
            except NetMikoAuthenticationException as e:
                failed[ip] = "Authentication failed"
                print(f"[AUTH FAIL] {ip}: {e}")
            except NetMikoTimeoutException as e:
                failed[ip] = "Timeout"
                print(f"[TIMEOUT] {ip}: {e}")
            except Exception as e:
                failed[ip] = str(e)
                print(f"[ERROR] {ip}: {e}")

    reachable = list(per_switch_vlans.keys())
    if not reachable:
        print("No reachable switches. Exiting.")
        sys.exit(0)

    # build union of VLANs
    all_vlan_ids = set()
    name_votes = defaultdict(Counter)
    vlan_presence = defaultdict(set)

    for ip, vmap in per_switch_vlans.items():
        all_vlan_ids.update(vmap.keys())
        for vid, vname in vmap.items():
            name_votes[vid][vname] += 1
            vlan_presence[vid].add(ip)

    rows = []
    for vid in sorted(all_vlan_ids, key=lambda x: int(x)):
        vname = name_votes[vid].most_common(1)[0][0]
        switches_with_vlan = sorted(vlan_presence[vid])
        rows.append({
            "VLAN_ID": vid,
            "VLAN_NAME": vname,
            "SWITCH_COUNT": len(switches_with_vlan),
            "SWITCHES": ";".join(switches_with_vlan),
        })

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_file = f"all_vlans_{str(subnet).replace('/', '_')}_{timestamp}.csv"

    with open(out_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["VLAN_ID", "VLAN_NAME", "SWITCH_COUNT", "SWITCHES"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nExported {len(rows)} VLANs to {out_file}")
    if failed:
        print("\nSkipped switches:")
        for ip, reason in failed.items():
            print(f"  - {ip}: {reason}")

if __name__ == "__main__":
    main()