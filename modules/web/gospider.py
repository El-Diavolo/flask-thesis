import subprocess
import re
import json
import os

def run_gospider(domain, output_dir="results/gospider"):
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{domain.replace('.', '_')}_gospider.json")
    
    # Run GoSpider
    command = ["gospider", "-s", f"http://{domain}","-c","10", "-o", output_dir, "-u", "web:hello"]
    subprocess.run(command, capture_output=True, text=True)

    # Compile regex for matching URLs with parameters and API endpoints
    param_url_regex = re.compile(r'http[s]?://[^?\s]+?\?[^=\s]+?=([^&\s]*)(?:&[^=\s]+?=([^&\s]*))*')
    api_url_regex = re.compile(r'http[s]?://[^/]+?/api/[^?\s]+(?:\?[^=\s]+?=[^\s]+)?')

    # Prepare data structure for JSON output
    extracted_urls = {"parameterized_urls": [], "api_endpoints": []}

    # Process GoSpider output files
    for root, _, files in os.walk(output_dir):
        for file in files:
            if file.startswith(domain.replace('.', '_')):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    for line in f:
                        # Check for URLs with parameters
                        if param_url_regex.search(line):
                            extracted_urls["parameterized_urls"].append(line.strip())
                        # Check for API endpoints
                        elif api_url_regex.search(line):
                            extracted_urls["api_endpoints"].append(line.strip())

    # Save extracted URLs into a JSON file
    with open(output_file, 'w') as jsonf:
        json.dump(extracted_urls, jsonf, indent=4)

    print(f"Extracted URLs have been saved to {output_file}")


