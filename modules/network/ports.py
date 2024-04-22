import nmap
import sys
import os
import json
import xmltodict

def scan_common_ports(target):
    nm = nmap.PortScanner()  # Initialize the PortScanner
    results_dir = "results/nmap"
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)  # Create the directory if it doesn't exist

    try:
        # Perform an Nmap scan on the target with a full TCP SYN scan
        nm.scan(target, arguments='-sS')
        print(f"Starting nmap scan on host: {target}")

        # Access the XML output from the last scan
        xml_output = nm.get_nmap_last_output()
        
        # Convert XML to JSON
        raw_json_result = xmltodict.parse(xml_output)
        
        # Filter and reformat the JSON output
        refined_result = {
            "host": target,
            "open_ports": []
        }

        # Extracting open ports and service information
        try:
            ports = raw_json_result['nmaprun']['host']['ports']['port']
            if isinstance(ports, list):  # Multiple ports
                for port in ports:
                    if port['state']['@state'] == 'open':
                        refined_result['open_ports'].append({
                            "port": port['@portid'],
                            "protocol": port['@protocol'],
                            "service": port.get('service', {}).get('@name', 'unknown')
                        })
            else:  # Single port
                if ports['state']['@state'] == 'open':
                    refined_result['open_ports'].append({
                        "port": ports['@portid'],
                        "protocol": ports['@protocol'],
                        "service": ports.get('service', {}).get('@name', 'unknown')
                    })
        except KeyError:  # Handle cases where no open ports are found
            print(f"No open ports found for {target}")

        # Define the path for the JSON output
        json_output_path = os.path.join(results_dir, f"{target.replace('/', '_').replace(':', '_')}_nmap_scan.json")

        # Save the refined JSON result
        with open(json_output_path, 'w') as json_file:
            json.dump(refined_result, json_file, indent=4)
        
        print(f"Nmap Scan was done succesfully, results saved in JSON format at {json_output_path}")
                    
    except nmap.PortScannerError:
        print("Nmap not found", sys.exc_info()[0])
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    target_domain = "scanme.nmap.org"
    scan_common_ports(target_domain)