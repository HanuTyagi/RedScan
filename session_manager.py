import json
import os
from datetime import datetime

TEMP_SESSION_FILE = "temp_session.json"

def get_current_session():
    """Returns the current session dictionary from the temp file. If none exists, return empty structure."""
    if not os.path.exists(TEMP_SESSION_FILE):
        return {
            "session_target": None,
            "focus_ip": None,
            "scan_history": [],
            "hosts": {} # "192.168.1.5": {status, hostnames, os_guesses, open_ports}
        }
    
    try:
        with open(TEMP_SESSION_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {
            "session_target": None,
            "focus_ip": None,
            "scan_history": [],
            "hosts": {}
        }

def save_current_session(session_data):
    """Writes the given session dictionary to the temp file."""
    with open(TEMP_SESSION_FILE, 'w') as f:
        json.dump(session_data, f, indent=4)

def update_session(target, insights):
    """
    Takes newly parsed insights from xml_parser and merges them into the current session.
    Prevents duplicates and updates existing data (like OS guesses or service names).
    """
    if not insights or not insights.get("hosts"):
        return

    session = get_current_session()
    
    # If the root target changed, reset the session explicitly
    if session["session_target"] != target:
        session = {
            "session_target": target,
            "focus_ip": None,
            "scan_history": [],
            "hosts": {}
        }

    # Iterate through the newly scanned hosts and merge
    for host in insights["hosts"]:
        
        # Determine the primary IP for this host
        primary_ip = None
        for addr in host["addresses"]:
            if addr["type"] == "ipv4":
                primary_ip = addr["addr"]
                break
        if not primary_ip and host["addresses"]:
            primary_ip = host["addresses"][0]["addr"]
            
        if not primary_ip: continue # Skip if no IP found
        
        # Initialize host structure if new
        if primary_ip not in session["hosts"]:
            session["hosts"][primary_ip] = {
                "status": "Unknown",
                "hostnames": [],
                "os_guesses": [],
                "open_ports": {}
            }
            
        h_record = session["hosts"][primary_ip]
        
        # Set Focus IP to the first live host if none exists yet
        if session["focus_ip"] is None and host["status"] == "up":
            session["focus_ip"] = primary_ip

        # Update Status
        if host["status"] != "Unknown":
            h_record["status"] = host["status"]
            
        # Merge Hostnames
        for hn in host["hostnames"]:
            if hn not in h_record["hostnames"]:
                h_record["hostnames"].append(hn)
        
        # Merge OS Guesses (keep the most accurate first)
        if host["os_matches"]:
            h_record["os_guesses"] = host["os_matches"]
            
        # Merge Open Ports
        for p in host["ports"]:
            if p["state"] == "open":
                port_id = str(p["port"])
                h_record["open_ports"][port_id] = {
                    "protocol": p["protocol"],
                    "service": p["service"],
                    "product": p["product"],
                    "version": p["version"]
                }
                
    save_current_session(session)

def add_history_log(command_str):
    """Appends a timestamped command string to the session history."""
    session = get_current_session()
    if session["session_target"]:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        session["scan_history"].append({"timestamp": timestamp, "command": command_str})
        save_current_session(session)

def set_focus_ip(ip):
    """Sets the focus IP for the dashboard."""
    session = get_current_session()
    if ip in session["hosts"]:
        session["focus_ip"] = ip
        save_current_session(session)
        return True
    return False

def clear_temp_files(temp_xml_file):
    """Deletes temporary files left over from unclean exits."""
    if os.path.exists(TEMP_SESSION_FILE):
        try:
            os.remove(TEMP_SESSION_FILE)
        except Exception:
            pass
            
    if os.path.exists(temp_xml_file):
        try:
            os.remove(temp_xml_file)
        except Exception:
            pass

def export_session(filepath):
    """Exports the temp session to a permanent file."""
    session = get_current_session()
    if not session["session_target"]:
        print("[!] Cannot save an empty session.")
        return False
        
    try:
        with open(filepath, 'w') as f:
            json.dump(session, f, indent=4)
        print(f"[*] Session saved successfully to {filepath}")
        return True
    except Exception as e:
        print(f"[!] Failed to save session: {e}")
        return False

def import_session(filepath):
    """Loads a saved session file into the temp session and returns the target IP."""
    if not os.path.exists(filepath):
        print(f"[!] File '{filepath}' not found.")
        return None
        
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            
        # Basic validation
        if "session_target" not in data or "hosts" not in data:
            print("[!] Invalid session file format.")
            return None
            
        save_current_session(data)
        print(f"[*] Session loaded successfully for target: {data['session_target']}")
        return data["session_target"]
    except Exception as e:
        print(f"[!] Failed to load session: {e}")
        return None
