import subprocess
import sys
import re
import os
import ctypes

# ==========================================
# 1. REDSCAN PRESET LIBRARY (NESTED ARCHITECTURE)
# ==========================================
PRESETS = {
    "1": {
        "category": "Reconnaissance & Discovery",
        "subcategories": {
            "A": {
                "name": "Standard & Reliable (No Scripts)",
                "scans": {
                    "1": {"name": "Ping Sweep (Host Discovery)", "aggressiveness": "Low (Safe/Quiet)", "description": "Quickly identifies live hosts without port scanning.", "flags": ["-sn", "-T4"], "scripts": [], "script_args": [], "requires_ports": False},
                    "2": {"name": "Top 100 Fast Sweep", "aggressiveness": "High (Fast/Loud)", "description": "Rapidly scans the 100 most common ports.", "flags": ["-F", "-T4"], "scripts": [], "script_args": [], "requires_ports": False},
                    "3": {"name": "Full TCP Surface Map", "aggressiveness": "Medium (Standard)", "description": "Scans all 65,535 TCP ports with OS and version detection.", "flags": ["-p-", "-sV", "-O", "-T4"], "scripts": [], "script_args": [], "requires_ports": False}
                }
            },
            "B": {
                "name": "Advanced Scripted Recon",
                "scans": {
                    "1": {"name": "Aggressive Map + DNS Brute", "aggressiveness": "Extreme (Loud/Intrusive)", "description": "Comprehensive scan combining OS detection and subdomain brute-forcing.", "flags": ["-A", "--min-rate", "5000"], "scripts": ["dns-brute"], "script_args": ["dns-brute.threads=10"], "requires_ports": True},
                    "2": {"name": "Internal Broadcast Discovery", "aggressiveness": "Low (Passive/Safe)", "description": "Uses broadcast pings/ARP to map subnets without direct targeting.", "flags": [], "scripts": ["broadcast-ping", "broadcast-arp-discovery"], "script_args": [], "requires_ports": False}
                }
            }
        }
    },
    "2": {
        "category": "Vulnerability & Evasion Tradecraft",
        "subcategories": {
            "A": {
                "name": "Targeted Audits",
                "scans": {
                    "1": {"name": "SMB Architecture & MS17-010 Audit", "aggressiveness": "High (Intrusive)", "description": "Deep inspection of SMB/RPC services.", "flags": ["-p", "139,445"], "scripts": ["smb-protocols", "smb-vuln-ms17-010"], "script_args": ["unsafe=1"], "requires_ports": False},
                    "2": {"name": "Automated CPE-to-CVE Fingerprinting", "aggressiveness": "High (Intrusive)", "description": "Forces maximum version detection and queries external CVE databases.", "flags": ["-sV", "--version-all"], "scripts": ["vulners"], "script_args": ["vulners.mincvss=7.0"], "requires_ports": True}
                }
            },
            "B": {
                "name": "Evasion & Stealth",
                "scans": {
                    "1": {"name": "Stateful Firewall Bypass (MTU)", "aggressiveness": "Low (Stealthy/Slow)", "description": "Fragments the TCP header to evade DPI and legacy IDS.", "flags": ["-f", "--mtu", "24", "--data-length", "15"], "scripts": [], "script_args": [], "requires_ports": True},
                    "2": {"name": "Asymmetric TCP (Xmas Tree)", "aggressiveness": "Low (Stealthy)", "description": "Bypasses stateless firewalls blocking SYN packets.", "flags": ["-sX", "--reason"], "scripts": [], "script_args": [], "requires_ports": True}
                }
            }
        }
    },
    "3": {
        "category": "Penetration Testing & CTF Triage",
        "subcategories": {
            "A": {
                "name": "Initial Foothold",
                "scans": {
                    "1": {"name": "The 'Kitchen Sink' (Aggressive)", "aggressiveness": "Extreme (Loud/Fast)", "description": "All ports, OS detection, versioning, default scripts.", "flags": ["-p-", "-A", "-T4"], "scripts": [], "script_args": [], "requires_ports": False},
                    "2": {"name": "HTTP Directory Enumeration", "aggressiveness": "High (Loud/Intrusive)", "description": "Brute-forces hidden web directories.", "flags": ["-p", "80,443"], "scripts": ["http-enum"], "script_args": [], "requires_ports": False}
                }
            }
        }
    }
}

# ==========================================
# 2. CORE LOGIC & VALIDATION ENGINES
# ==========================================
def check_privileges():
    """Checks if the script is running with Root/Administrator privileges."""
    try:
        return os.geteuid() == 0  # Unix/Linux
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows

def is_ip_address(target):
    """Checks if the target is an IP or localhost to prevent script errors."""
    if not target: return False
    if target.lower() in ["localhost", "127.0.0.1"]: return True
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$", target))

def pre_flight_checks(scan_data, target, port_flags, is_root):
    """Linter for Nmap commands to prevent runtime script or syntax errors."""
    warnings = []
    scripts = scan_data.get("scripts", [])
    flags = scan_data.get("flags", [])
    all_flags = flags + port_flags

    # Check 1: DNS Brute-forcing on an IP Address
    if "dns-brute" in scripts and is_ip_address(target):
        warnings.append(
            "[!] SCRIPT CONFLICT: 'dns-brute' requires a domain name (e.g., target.com).\n"
            f"    You provided an IP/Localhost ('{target}'). Nmap will fail this script."
        )

    # Check 2: SMB Scripts without restricted ports
    if any(s.startswith("smb-") for s in scripts):
        if not any("-p" in f for f in all_flags) and "-p-" not in all_flags:
            warnings.append(
                "[!] EFFICIENCY WARNING: Running SMB scripts without restricting to ports 139/445.\n"
                "    This will scan unnecessary ports and heavily delay the output."
            )

    # Check 3: Connect Scan (-sT) fundamentally conflicts with Fragmentation (-f)
    if "-sT" in all_flags and ("-f" in all_flags or "--mtu" in all_flags):
        warnings.append(
            "[!] FATAL CONFLICT: TCP Connect scans (-sT) rely on the OS socket API and cannot be fragmented (-f/--mtu).\n"
            "    The orchestrator will likely crash."
        )

    # Check 4: Root Privilege Verification for Raw Sockets
    privileged_flags = ["-O", "-sS", "-sU", "-f", "-sX"]
    if not is_root and any(flag in all_flags for flag in privileged_flags):
        warnings.append(
            "[!] PRIVILEGE WARNING: This scan utilizes raw socket flags (e.g., -sS, -O, -f) which require Root/Admin privileges.\n"
            "    Nmap will likely fail or forcefully downgrade your scan to a standard TCP Connect (-sT)."
        )

    return warnings

def get_port_selection():
    """Prompts the user for port scoping."""
    print("\n--- Port Selection ---")
    print("  [1] Frequently Used Ports (Top 1000)")
    print("  [2] All 65,535 Ports (-p-)")
    print("  [3] Custom Ports (e.g., 80,443,8080)")

    choice = input("Select Scope > ").strip()
    if choice == '2': return ["-p-"]
    if choice == '3': return ["-p", input("Enter ports: ").strip()]
    return []

def build_and_run_scan(scan_data, target, is_root):
    """Assembles the command string and handles subprocess execution."""
    port_flags = get_port_selection() if scan_data.get("requires_ports", True) else []

    # Execute Pre-Flight Checks
    warnings = pre_flight_checks(scan_data, target, port_flags, is_root)
    if warnings:
        print("\n" + "!"*60)
        print(" PRE-FLIGHT VALIDATION WARNINGS DETECTED ")
        print("!"*60)
        for w in warnings: print(w + "\n")
        print("!"*60)

        if input("Do you want to force execution anyway? (y/N): ").strip().lower() != 'y':
            print("[*] Scan aborted. Returning to menu.")
            return

    # Construct Command
    command = ["nmap"] + scan_data["flags"] + port_flags
    
    if "output_xml" in scan_data and scan_data["output_xml"]:
        command.extend(["-oX", scan_data["output_xml"]])

    if scan_data["scripts"]:
        command.extend(["--script", ",".join(scan_data["scripts"])])
    if scan_data["script_args"]:
        command.extend(["--script-args", ",".join(scan_data["script_args"])])

    command.append(target)

    print("\n" + "="*60)
    print(f"[*] ORCHESTRATOR ENGAGED")
    print(f"[*] Command: {' '.join(command)}")
    print("="*60 + "\n")

    # Subprocess execution to stream stdout
    process = None
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end="")
        process.wait()
        print("\n" + "="*60 + "\n[*] Scan Complete.\n" + "="*60)
        return True, " ".join(command) # Indicate success and return command
    except FileNotFoundError:
        print("[!] Critical Error: Nmap binary not found in system PATH.")
        return False, ""
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")
        if process:
            process.terminate()
        return False, ""

# ==========================================
# 3. INTERFACE ORCHESTRATOR
# ==========================================
def main():
    current_target = None
    is_root = check_privileges()

    # Format the privilege string for the dashboard
    privilege_status = "ROOT / ADMIN" if is_root else "STANDARD USER (Raw socket scans will fail)"

    while True:
        print("\n" + "#"*60)
        print("    REDSCAN: NMAP ORCHESTRATOR CLI")
        print("#"*60)

        # Display Status Dashboard
        print(f"\n[ Target     : {current_target if current_target else 'NOT SET'} ]")
        print(f"[ Privileges : {privilege_status} ]\n")

        print("  [T] Set Target IP / Domain")
        for key, value in PRESETS.items():
            print(f"  [{key}] {value['category']}")
        print("  [0] Exit")

        main_choice = input("\nSelect > ").strip().upper()

        if main_choice == '0': sys.exit(0)
        if main_choice == 'T':
            current_target = input("Enter Target: ").strip()
            continue

        if main_choice not in PRESETS:
            print("[!] Invalid selection.")
            continue

        if not current_target:
            print("[!] Error: You must set a target (Option T) first.")
            continue

        selected_category = PRESETS[main_choice]

        # Subcategory Loop
        while True:
            print(f"\n--- {selected_category['category'].upper()} ---")
            for sub_key, sub_val in selected_category["subcategories"].items():
                print(f"  [{sub_key}] {sub_val['name']}")
            print("  [R] Return to Main Menu")

            sub_choice = input("\nSelect Subcategory > ").strip().upper()
            if sub_choice == 'R': break

            if sub_choice in selected_category["subcategories"]:
                selected_sub = selected_category["subcategories"][sub_choice]

                # Scan Loop
                while True:
                    print(f"\n--- {selected_sub['name'].upper()} ---")
                    for scan_key, scan_val in selected_sub["scans"].items():
                        name = scan_val['name']
                        agg = scan_val.get('aggressiveness', 'Unknown')
                        desc = scan_val['description']

                        print(f"  [{scan_key}] {name} [{agg}]")
                        print(f"      └─ {desc}")
                    print("  [R] Return to Subcategories")

                    scan_choice = input("\nSelect Scan > ").strip().upper()
                    if scan_choice == 'R': break

                    if scan_choice in selected_sub["scans"]:
                        build_and_run_scan(selected_sub["scans"][scan_choice], current_target, is_root)
                        input("\nPress Enter to return to menu...")
                        break
                    else:
                        print("[!] Invalid scan selection.")
            else:
                print("[!] Invalid subcategory.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting RedScan. Goodbye!")
        sys.exit(0)
