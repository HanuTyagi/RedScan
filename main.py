import sys
import os
import scan
import xml_parser
import session_manager
import port_prober

def main():
    current_target = None
    is_root = scan.check_privileges()

    # Format the privilege string for the dashboard
    privilege_status = "ROOT / ADMIN" if is_root else "STANDARD USER (Raw socket scans will fail)"
    temp_xml_file = "temp_scan_results.xml"

    # Cleanup any stale state
    session_manager.clear_temp_files(temp_xml_file)

    while True:
        # Load active session for dashboard
        session = session_manager.get_current_session()
        
        print("\n" + "#"*60)
        print("    REDSCAN: SMART ORCHESTRATOR CLI")
        print("#"*60)

        # Display Status Dashboard
        print(f"\n[ Session Target : {current_target if current_target else 'NOT SET'} ]")
        print(f"[ Privileges     : {privilege_status} ]")
        
        # Display cumulative Session Data
        if current_target and session and session.get("session_target") == current_target:
            hosts = session.get("hosts", {})
            live_hosts = sum(1 for h in hosts.values() if h["status"] == "up")
            focus_ip = session.get("focus_ip", None)
            
            print(f"[ Live Hosts     : {live_hosts} ]")
            
            if focus_ip and focus_ip in hosts:
                h_data = hosts[focus_ip]
                print(f"[ Focus Host     : {focus_ip} ]")
                
                os_guesses = h_data.get("os_guesses", [])
                if os_guesses:
                    print(f"  └─ Base OS     : {os_guesses[0]['name']} ({os_guesses[0]['accuracy']}%)")
                
                ports = h_data.get("open_ports", {})
                if ports:
                    port_list = []
                    for p_id in sorted([int(k) for k in ports.keys()]):
                        service = ports[str(p_id)]['service']
                        port_list.append(f"{p_id}({service})")
                    print(f"  └─ Open Ports  : {', '.join(port_list)}")
                else:
                    print("  └─ Open Ports  : None discovered yet")
        print()
        
        print("  [T] Set Target IP / Subnet / Domain")
        print("  [F] Change Host Focus")
        print("  [P] Port Prober  (Smart Pre-scan)")
        for key, value in scan.PRESETS.items():
            print(f"  [{key}] {value['category']}")
        print("  [S] Session Management (Save/Load)")
        print("  [0] Exit")

        main_choice = input("\nSelect > ").strip().upper()

        if main_choice == '0':
            print("\nExiting RedScan. Goodbye!")
            session_manager.clear_temp_files(temp_xml_file)
            sys.exit(0)
            
        if main_choice == 'T':
            current_target = input("Enter Target (IP or CIDR like 192.168.1.0/24): ").strip()
            continue
            
        if main_choice == 'P':
            if not current_target:
                print("[!] Error: You must set a target (Option T) first.")
                continue

            # Port range selection
            print("\n--- PORT PROBER RANGE ---")
            print("  [1] Full Scan (1-65535) — Recommended")
            print("  [2] Common Ports (1-1024)")
            print("  [3] Custom Range")
            pr_choice = input("\nSelect > ").strip()

            start_p, end_p = 1, 65535
            if pr_choice == '2':
                start_p, end_p = 1, 1024
            elif pr_choice == '3':
                try:
                    start_p = int(input("Start Port: ").strip())
                    end_p   = int(input("End Port  : ").strip())
                except ValueError:
                    print("[!] Invalid range. Using 1-65535.")
                    start_p, end_p = 1, 65535

            # Run the probe
            open_ports, timing, avg_c = port_prober.launch_probe(
                current_target, start_p, end_p
            )

            # Results
            print(f"\n{'='*60}")
            print(f"  PROBE COMPLETE")
            print(f"{'='*60}")
            if open_ports:
                port_str = ','.join(str(p) for p in open_ports)
                print(f"  Open Ports : {port_str}")
            else:
                print("  Open Ports : None found")
            print(f"  Avg Speed  : {avg_c} concurrent connections")
            print(f"  Nmap Timing: {timing} (suggested)")
            print(f"{'='*60}")

            if not open_ports:
                input("\nPress Enter to return to menu...")
                continue

            # Handoff options
            print("\n  [1] Send open ports to an Nmap Scan")
            print("  [2] Save ports to session and return")
            handoff = input("\nSelect > ").strip()

            if handoff == '2':
                # Register a synthetic event in session
                session_manager.add_history_log(
                    f"[PORT PROBER] Found {len(open_ports)} open ports: {port_str}"
                )
                input("\nPorts saved. Press Enter to return...")
                continue

            # --- Nmap handoff: drop into category menu with ports pre-set ---
            injected_ports = port_str  # keep as string for reuse below

            print("\n--- SELECT SCAN CATEGORY ---")
            for key, value in scan.PRESETS.items():
                print(f"  [{key}] {value['category']}")
            print("  [R] Return to Main Menu")

            cat_sel = input("\nSelect Category > ").strip().upper()
            if cat_sel == 'R' or cat_sel not in scan.PRESETS:
                continue

            sel_cat = scan.PRESETS[cat_sel]

            print(f"\n--- {sel_cat['category'].upper()} ---")
            for sub_key, sub_val in sel_cat["subcategories"].items():
                print(f"  [{sub_key}] {sub_val['name']}")
            print("  [R] Go Back")

            sub_sel = input("\nSelect Subcategory > ").strip().upper()
            if sub_sel == 'R' or sub_sel not in sel_cat["subcategories"]:
                continue

            sel_sub = sel_cat["subcategories"][sub_sel]

            print(f"\n--- {sel_sub['name'].upper()} ---")
            for scan_key, scan_val in sel_sub["scans"].items():
                print(f"  [{scan_key}] {scan_val['name']} [{scan_val.get('aggressiveness', '?')}]")
                print(f"      └─ {scan_val['description']}")
            print("  [R] Go Back")

            scan_sel = input("\nSelect Scan > ").strip().upper()
            if scan_sel == 'R' or scan_sel not in sel_sub["scans"]:
                continue

            # Build the scan data — inject prober ports and suggested timing
            prober_scan_data = sel_sub["scans"][scan_sel].copy()
            prober_scan_data["output_xml"] = temp_xml_file
            # Override port flags: inject discovered ports + suggested timing
            prober_scan_data["flags"] = (
                [timing] +
                [f for f in prober_scan_data["flags"] if not f.startswith("-T")] +
                ["-p", injected_ports]
            )
            prober_scan_data["requires_ports"] = False  # skip port prompt

            success, cmd_str = scan.build_and_run_scan(
                prober_scan_data, current_target, is_root
            )

            if success:
                session_manager.add_history_log(cmd_str)
                print("\n[*] Analyzing Scan Results...")
                insights = xml_parser.parse_nmap_xml(temp_xml_file)
                if insights:
                    session_manager.update_session(current_target, insights)
                    xml_parser.display_insights(insights)
                if os.path.exists(temp_xml_file):
                    os.remove(temp_xml_file)

            input("\nPress Enter to return to menu...")
            continue

        if main_choice == 'F':
            if session and session.get("hosts"):
                print("\n--- SELECT FOCUS HOST ---")
                live_ips = [ip for ip, data in session["hosts"].items() if data["status"] == "up"]
                if not live_ips:
                    print("[!] No live hosts discovered yet.")
                    continue
                    
                for idx, ip in enumerate(live_ips, 1):
                    # Quick snippet of port count to make choice easier
                    p_count = len(session["hosts"][ip]["open_ports"])
                    print(f"  [{idx}] {ip} ({p_count} open ports)")
                    
                sel = input("\nSelect Host Number > ").strip()
                if sel.isdigit() and 1 <= int(sel) <= len(live_ips):
                    session_manager.set_focus_ip(live_ips[int(sel)-1])
                else:
                    print("[!] Invalid selection.")
            else:
                print("[!] No active session data to focus on. Run a scan first.")
            continue

        if main_choice == 'S':
            print("\n--- SESSION MANAGEMENT ---")
            print("  [1] Save Current Target Session")
            print("  [2] Load Saved Session")
            print("  [3] Clear Active Session")
            print("  [4] View Scan History")
            print("  [5] Smart Copy: Open Ports (Focus Host)")
            print("  [6] Smart Copy: All Live IPs")
            print("  [R] Go Back")
            s_choice = input("\nSelect > ").strip().upper()
            
            if s_choice == '1':
                fname = input("Enter output filename (e.g., target_audit.json): ").strip()
                if fname: session_manager.export_session(fname)
            elif s_choice == '2':
                fname = input("Enter path to saved session to load: ").strip()
                result = session_manager.import_session(fname)
                if result: current_target = result # Set the loaded target
            elif s_choice == '3':
                session_manager.clear_temp_files(temp_xml_file)
                current_target = None
                print("[*] Session cleared successfully.")
            elif s_choice == '4':
                if session and session.get("scan_history"):
                    print("\n--- SCAN HISTORY ---")
                    for log in session["scan_history"]:
                        print(f"[{log['timestamp']}] {log['command']}")
                else:
                    print("[!] No scan history available.")
            elif s_choice == '5':
                if session and session.get("focus_ip") and session["hosts"]:
                    f_ip = session["focus_ip"]
                    ports = session["hosts"][f_ip]["open_ports"].keys()
                    if ports:
                        csv = ",".join(sorted(ports, key=int))
                        print(f"\n[*] Open Ports for {f_ip}:\n\n{csv}\n")
                    else:
                        print("[!] No open ports listed for Focus IP.")
                else:
                    print("[!] Set a Focus IP and scan first.")
            elif s_choice == '6':
                if session and session.get("hosts"):
                    live_ips = [ip for ip, data in session["hosts"].items() if data["status"] == "up"]
                    if live_ips:
                        csv = ",".join(live_ips)
                        print(f"\n[*] Live IPs:\n\n{csv}\n")
                    else:
                        print("[!] No live IPs listed.")
                else:
                    print("[!] No active session data.")
            
            input("\nPress Enter to return to menu...")
            continue

        if main_choice not in scan.PRESETS:
            print("[!] Invalid selection.")
            continue

        if not current_target:
            print("[!] Error: You must set a target (Option T) first.")
            continue

        selected_category = scan.PRESETS[main_choice]

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
                        selected_scan_data = selected_sub["scans"][scan_choice].copy()
                        selected_scan_data["output_xml"] = temp_xml_file
                        
                        success, cmd_str = scan.build_and_run_scan(selected_scan_data, current_target, is_root)
                        
                        if success:
                            # Log to history
                            session_manager.add_history_log(cmd_str)
                        
                            # Pass to XML Parser
                            print("\n[*] Analyzing Scan Results...")
                            insights = xml_parser.parse_nmap_xml(temp_xml_file)
                            
                            # Merge into ongoing Session
                            if insights:
                                session_manager.update_session(current_target, insights)
                                xml_parser.display_insights(insights)
                            
                            # Clean up XML but leave Session JSON!
                            if os.path.exists(temp_xml_file):
                                os.remove(temp_xml_file)
                        
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
        session_manager.clear_temp_files("temp_scan_results.xml")
        sys.exit(0)
