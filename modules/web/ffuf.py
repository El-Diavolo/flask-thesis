import subprocess
import os
import json

def load_online_subdomains(hosts_dir_path):
    online_subdomains = []
    if not os.path.exists(hosts_dir_path):
        print(f"Directory not found: {hosts_dir_path}")
        return online_subdomains

    for filename in os.listdir(hosts_dir_path):
        if filename.endswith('.json'):
            full_path = os.path.join(hosts_dir_path, filename)
            try:
                with open(full_path, 'r') as file:
                    data = json.load(file)
                    if 'online' in data:
                        for sub, details in data['online'].items():
                            if details.get('status_code') in [200, 301]:
                                online_subdomains.append(sub)
            except json.JSONDecodeError:
                print(f"Error decoding JSON from {filename}")
            except FileNotFoundError:
                print(f"File not found: {filename}")
    return online_subdomains

def run_ffuf(subdomain, wordlist, results_dir):
    result_file = os.path.join(results_dir, f'{subdomain.replace(":", "_").replace("/", "_")}_ffuf.json')
    os.makedirs(results_dir, exist_ok=True)
    
    command = ['ffuf', '-w', wordlist, '-u', f'http://{subdomain}/FUZZ', '-fc', '401,403,500','-r',
               '-o', result_file, '-of', 'json']
    try:
        subprocess.run(command, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        print(f"ffuf timed out for {subdomain}")
    except subprocess.CalledProcessError as e:
        print(f"Error running ffuf for {subdomain}: {str(e)}")

def reformat_results(results):
    formatted_results = []
    for result in results:
        formatted_result = {
            'url': result['url'],
            'status': result['status'],
            'redirectlocation': result.get('redirectlocation', 'N/A'),
            'FUZZ': result['input']['FUZZ']
        }
        formatted_results.append(formatted_result)
    return formatted_results

def compile_ffuf_results(results_dir, target):
    compiled_results = {}
    for filename in os.listdir(results_dir):
        if filename.endswith('_ffuf.json'):
            full_path = os.path.join(results_dir, filename)
            subdomain = filename[:-10].replace("_", ":").replace("_", "/")
            try:
                with open(full_path, 'r') as file:
                    data = json.load(file)
                    if 'results' in data:
                        compiled_results[subdomain] = reformat_results(data['results'])
                os.remove(full_path)
            except json.JSONDecodeError:
                print(f"Failed to decode JSON for {filename}")

    compiled_file_name = f"{target.replace(':', '_').replace('/', '_')}_ffuf_results.json"
    compiled_file_path = os.path.join(results_dir, compiled_file_name)
    with open(compiled_file_path, 'w') as file:
        json.dump(compiled_results, file, indent=4)

def read_subdomains_and_run_ffuf(target, hosts_dir_path, wordlist_path, results_dir):
    online_subdomains = load_online_subdomains(hosts_dir_path)
    for subdomain in online_subdomains:
        run_ffuf(subdomain, wordlist_path, results_dir)
    compile_ffuf_results(results_dir, target)
    print(f"Compiled ffuf results for {target} saved to {results_dir}")

if __name__ == "__main__":
    target = "testphp.vulnweb.com"
    hosts_dir_path = "/mnt/d/flask-thesis/results/hosts"
    wordlist_path = "/mnt/d/flask-thesis/test/test.txt"
    results_dir = "/mnt/d/flask-thesis/results/directories"
    read_subdomains_and_run_ffuf(target, hosts_dir_path, wordlist_path, results_dir)
