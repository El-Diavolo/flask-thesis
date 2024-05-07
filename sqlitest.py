import subprocess
import os
import json
import logging
from threading import Thread
from queue import Queue

# Set up logging for debugging and progress monitoring
def setup_logger():
    logger = logging.getLogger("SQLI_Detection")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    return logger

# Run gau to collect URLs from the given domain
def run_gau(target_domain, output_file):
    logger = setup_logger()
    command = ["gau", target_domain, "--o", output_file]
    try:
        subprocess.run(command, check=True)
        logger.info(f"gau completed for {target_domain}, results saved to {output_file}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to run gau for {target_domain}: {str(e)}")

# Filter SQL injection-prone URLs using gf
def filter_sqli_urls(input_file, output_file):
    logger = setup_logger()
    command = ["gf", "sqli", input_file]
    with open(output_file, 'w') as outfile:
        subprocess.run(command, stdout=outfile)
        logger.info(f"Filtered SQLi URLs and written to {output_file}")

# Function to run sqlmap on a single URL
def run_sqlmap_on_url(url, output_queue):
    logger = setup_logger()
    command = [
        "sqlmap",
        "-u", url,
        "--level", "5",
        "--risk", "3",
        "--batch",
        "--dbms", "mysql",
        "--tamper", "between"
    ]

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
        output_queue.put((url, result.stdout))
        logger.info(f"sqlmap completed for {url}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to run sqlmap on {url}: {str(e)}")
        output_queue.put((url, None))
    except subprocess.TimeoutExpired:
        logger.warning(f"sqlmap scan timed out for {url}")
        output_queue.put((url, "Timeout expired"))

# Thread worker function
def worker(url_queue, output_queue):
    while not url_queue.empty():
        url = url_queue.get()
        run_sqlmap_on_url(url, output_queue)
        url_queue.task_done()

# Main function to handle threads and process URLs
def run_sqlmap_on_all_urls(sqli_file, json_output):
    urls = []
    with open(sqli_file, 'r') as file:
        urls = [line.strip() for line in file if line.strip()]

    url_queue = Queue()
    output_queue = Queue()

    for url in urls:
        url_queue.put(url)

    # Start a pool of threads
    threads = []
    for _ in range(10):  # Adjust number of threads based on your needs
        t = Thread(target=worker, args=(url_queue, output_queue))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    url_queue.join()

    # Collect all results
    results = []
    while not output_queue.empty():
        url, output = output_queue.get()
        if output:
            results.append({"url": url, "output": output})

    # Save results to JSON
    with open(json_output, 'w') as json_file:
        json.dump(results, json_file, indent=4)
    parse_directory_json(json_output)

def parse_directory_json(json_output):
    with open(json_output, 'r') as file:
        data = json.load(file)

    parsed_data = []
    for entry in data:
        outputs = entry["output"].split('\n')
        parsed_entry = {"url": entry["url"], "vulnerabilities": []}
        vulnerability_info = {}

        for line in outputs:
            if "Payload:" in line:
                vulnerability_info["payload"] = line.split("Payload:")[1].strip()
            elif "back-end DBMS:" in line:
                dbms_info = line.split("back-end DBMS:")[1].strip()
                if '>=' in dbms_info:
                    dbms, version = dbms_info.split('>=')
                    vulnerability_info["dbms"] = dbms.strip()
                    vulnerability_info["dbms_version"] = version.strip()
                else:
                    vulnerability_info["dbms"] = dbms_info.strip()
            elif "web server operating system:" in line:
                vulnerability_info["server_os"] = line.split("web server operating system:")[1].strip()

        if vulnerability_info:  # Add only if there's meaningful info
            parsed_entry["vulnerabilities"].append(vulnerability_info)
        
        if parsed_entry["vulnerabilities"]:
            parsed_data.append(parsed_entry)

    with open(json_output, 'w') as file:
        json.dump(parsed_data, file, indent=4)




# Main function to run gau, filter URLs, and execute sqlmap
def sqli_scan(target_domain):
    output_dir = "/mnt/d/flask-thesis/results/sqli"
    os.makedirs(output_dir, exist_ok=True)

    gau_file = os.path.join(output_dir, "fgau.txt")
    sqli_file = os.path.join(output_dir, "sqli_filtered.txt")
    json_output = os.path.join(output_dir, "sqli_results.json")

    run_gau(target_domain, gau_file)
    filter_sqli_urls(gau_file, sqli_file)
    run_sqlmap_on_all_urls(sqli_file, json_output)

# Entry point for the script
if __name__ == "__main__":
    target_domain = "testphp.vulnweb.com"
    sqli_scan(target_domain)
