import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor

def run_single_nuclei_scan(host, output_file):
    """
    Function to run a Nuclei scan on a single host and save the output to a file.
    """
    command = ["nuclei","-as", "-u", host, "-o", output_file]
    try:
        subprocess.run(command, check=True , stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 
        print(f"[+] Nuclei scan completed for {host}. Results saved to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running Nuclei on {host}: {e}")

def run_nuclei_scan(hosts_dir='results/hosts', output_dir='results/nuclei', threads=1000):
    os.makedirs(output_dir, exist_ok=True)  

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []

        for filename in os.listdir(hosts_dir):
            if filename.endswith('.json'):
                with open(os.path.join(hosts_dir, filename), 'r') as file:
                    data = json.load(file)
                    online_hosts = data.get('online', {})

                    for host, details in online_hosts.items():
                        if details.get('status_code') in [200, 301]:
                            output_file = os.path.join(output_dir, f'nuclei_{host.replace(".", "_").replace(":", "_")}.txt')
                            print(f"[*] Queuing Nuclei scan for {host}")
                            futures.append(executor.submit(run_single_nuclei_scan, host, output_file))

        for future in futures:
            future.result()  # Wait for all futures to complete

if __name__ == "__main__":
    run_nuclei_scan()
