import xml.etree.ElementTree as ET
import os

def parse_nmap_xml(xml_file):
    """Parses an Nmap XML output file and returns structured insights."""
    if not os.path.exists(xml_file):
        print(f"[!] XML Parser Error: File '{xml_file}' not found.")
        return None

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[!] XML Parser Error: Failed to parse '{xml_file}'. Exception: {e}")
        return None

    scan_info = {
        "start_time": root.attrib.get('startstr', 'Unknown'),
        "args": root.attrib.get('args', 'Unknown'),
        "hosts": []
    }

    for host in root.findall('host'):
        host_data = {
            "addresses": [],
            "status": "Unknown",
            "hostnames": [],
            "ports": [],
            "os_matches": []
        }

        # Status
        status_elem = host.find('status')
        if status_elem is not None:
            host_data["status"] = status_elem.attrib.get('state', 'Unknown')

        # Addresses
        for addr in host.findall('address'):
            host_data["addresses"].append({
                "addr": addr.attrib.get('addr'),
                "type": addr.attrib.get('addrtype')
            })

        # Hostnames
        hostnames_elem = host.find('hostnames')
        if hostnames_elem is not None:
            for hname in hostnames_elem.findall('hostname'):
                host_data["hostnames"].append(hname.attrib.get('name'))

        # Ports
        ports_elem = host.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_id = port.attrib.get('portid')
                protocol = port.attrib.get('protocol')
                state_elem = port.find('state')
                state = state_elem.attrib.get('state') if state_elem is not None else 'Unknown'
                
                service_elem = port.find('service')
                service_name = service_elem.attrib.get('name') if service_elem is not None else 'Unknown'
                service_product = service_elem.attrib.get('product', '') if service_elem is not None else ''
                service_version = service_elem.attrib.get('version', '') if service_elem is not None else ''

                # Scripts attached to this port
                scripts = []
                for script in port.findall('script'):
                    scripts.append({
                        "id": script.attrib.get('id'),
                        "output": script.attrib.get('output')
                    })

                host_data["ports"].append({
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "product": service_product,
                    "version": service_version,
                    "scripts": scripts
                })
        
        # OS Detection
        os_elem = host.find('os')
        if os_elem is not None:
            for os_match in os_elem.findall('osmatch'):
                host_data["os_matches"].append({
                    "name": os_match.attrib.get('name'),
                    "accuracy": os_match.attrib.get('accuracy')
                })
        
        scan_info["hosts"].append(host_data)

    return scan_info


def display_insights(scan_info):
    """Takes parsed structured data and prints human-readable insights."""
    if not scan_info:
        return

    print("\n" + "="*60)
    print(" 🚀 SMART SCAN INSIGHTS ".center(60, '='))
    print("="*60)
    print(f"[*] Command run : {scan_info['args']}")
    print(f"[*] Start Time  : {scan_info['start_time']}")

    for idx, host in enumerate(scan_info["hosts"], 1):
        print(f"\n[HOST {idx}]")
        
        # IP & Status
        primary_ip = next((a['addr'] for a in host['addresses'] if a['type'] == 'ipv4'), host['addresses'][0]['addr'] if host['addresses'] else 'Unknown')
        print(f"  > IP Address  : {primary_ip}")
        print(f"  > Status      : {host['status'].upper()}")
        
        if host['hostnames']:
            print(f"  > Hostnames   : {', '.join(host['hostnames'])}")

        # OS Estimates
        if host['os_matches']:
            best_os = host['os_matches'][0]
            print(f"  > OS Guess    : {best_os['name']} ({best_os['accuracy']}% accuracy)")

        # Port Insights
        open_ports = [p for p in host['ports'] if p['state'] == 'open']
        if open_ports:
            print(f"  > Open Ports  : {len(open_ports)}")
            print("    --------------------------------------------------------")
            print("    PORT     STATE  SERVICE      VERSION")
            print("    --------------------------------------------------------")
            
            for p in open_ports:
                version_str = f"{p['product']} {p['version']}".strip()
                print(f"    {p['port']:<8} {p['state']:<6} {p['service']:<12} {version_str}")
                
                # Check for critical ports
                critical_ports = {
                    "21": "FTP - Potentially insecure file transfer.",
                    "22": "SSH - Check for weak credentials or outdated version.",
                    "23": "Telnet - Highly insecure, unencrypted protocol.",
                    "3389": "RDP - Remote Desktop, high-value target for ransomware.",
                    "445": "SMB - Ensure patched against EternalBlue (MS17-010).",
                    "139": "NetBIOS - Can enumerate users and shares."
                }
                
                if str(p['port']) in critical_ports:
                    print(f"      [!] CRITICAL: {critical_ports[str(p['port'])]}")
                
                # Print script output if any
                for script in p['scripts']:
                    print(f"      [*] Script ({script['id']}):")
                    for line in script['output'].split('\\n'): # Handle escaped newlines
                        print(f"          {line.strip()}")
            print("    --------------------------------------------------------")
        else:
            print("  > Ports       : No open ports discovered.")
        
    print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        data = parse_nmap_xml(sys.argv[1])
        display_insights(data)
    else:
        print("Usage: python3 xml_parser.py <nmap.xml>")
