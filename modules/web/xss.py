import subprocess
import os
import json
import glob
import logging
import re
import urllib.parse

# Set up logging for debugging
def setup_logger():
    logger = logging.getLogger('XSS_Detection')
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    return logger

# Extract URLs that contain known XSS vulnerabilities
def filter_xss_urls(input_file, xss_file):
    logger = setup_logger()
    with open(xss_file, 'w') as output:
        command = ["gf", "xss", input_file]
        subprocess.run(command, stdout=output)
    logger.info(f"XSS URLs filtered and written to {xss_file}")

# Run XSSVibe on the URLs
def run_xssvibe(xss_output, xssvibe_results_file):
    xssvibes_dir = "/opt/xss_vibes"
    os.chdir(xssvibes_dir)
    command = ["python3", "main.py", "-f", xss_output, "-o", xssvibe_results_file, "-t", "100"]
    try:
        subprocess.run(command, check=True)
        print(f"XSSVibe successfully processed and output saved to {xssvibe_results_file}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to run XSSVibe: {e}")

# Run Dalfox on the URLs to find potential vulnerabilities
def run_dalfox(xss_output, dalfox_results_file):
    command = ["dalfox", "file", xss_output, "-o", dalfox_results_file, "--custom-alert-value", "calfcrusher", "--waf-evasion", "-F"]
    try:
        subprocess.run(command, check=True)
        print(f"Dalfox output saved to {dalfox_results_file}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to run Dalfox: {e}")

# Extract vulnerable URLs from Dalfox results, focusing on [POC] tags
def extract_dalfox_vulnerable_urls(dalfox_results_file):
    logger = setup_logger()
    vulnerable_urls = []
    with open(dalfox_results_file, 'r') as file:
        for line in file:
            if "[POC]" in line:
                url_match = re.search(r'https?://\S+', line)
                if url_match:
                    url = url_match.group()
                    payload = line.strip()
                    vulnerable_urls.append({
                        "url": url,
                        "payload": payload
                    })
    return vulnerable_urls

# Compile results into a JSON output
def compile_results_to_json(xss_dir, target_domain, final_json_output):
    logger = setup_logger()
    all_results = []

    # Extract from XSSVibe results
    xssvibe_results_file = os.path.join(xss_dir, f"xssvibe_results_{target_domain}.txt")
    with open(xssvibe_results_file, 'r') as file:
        for line in file:
            url_match = re.search(r'https?://\S+', line)
            if url_match:
                url = url_match.group()
                all_results.append({
                    "url": url,
                    "payload": "XSSVibe"
                })

    # Extract from Dalfox results with [POC]
    dalfox_results_file = os.path.join(xss_dir, f"dalfox_results_{target_domain}.txt")
    vulnerable_urls = extract_dalfox_vulnerable_urls(dalfox_results_file)
    all_results.extend(vulnerable_urls)

    # Save to JSON
    with open(final_json_output, 'w') as file:
        json.dump(all_results, file, indent=4)
    logger.info(f"Compiled JSON results saved to {final_json_output}")

def run_xss():
    katana_dir = "/mnt/d/flask-thesis/results/katana"
    xss_dir = "/mnt/d/flask-thesis/results/xss"
    os.makedirs(xss_dir, exist_ok=True)

    for katana_output in glob.glob(os.path.join(katana_dir, '*')):
        target_domain = os.path.basename(katana_output).replace("_", ".").replace(".txt", "")
        urls_xss_path = os.path.join(xss_dir, f"urls_xss_{target_domain}.txt")
        xssvibe_results_file = os.path.join(xss_dir, f"xssvibe_results_{target_domain}.txt")
        dalfox_results_file = os.path.join(xss_dir, f"dalfox_results_{target_domain}.txt")
        final_json_output = os.path.join(xss_dir, f"final_xss_results_{target_domain}.json")

        filter_xss_urls(katana_output, urls_xss_path)
        run_xssvibe(urls_xss_path, xssvibe_results_file)
        run_dalfox(urls_xss_path, dalfox_results_file)

        compile_results_to_json(xss_dir, target_domain, final_json_output)

if __name__ == "__main__":
    run_xss()
