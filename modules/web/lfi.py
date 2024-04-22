import subprocess
import os
import json
import glob
import logging
import re
import time

def setup_logger():
    logger = logging.getLogger('LFI_Detection')
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    return logger

def filter_lfi_urls(input_file, lfi_file):
    logger = setup_logger()
    if not os.path.exists(input_file):
        logger.error(f"Input file {input_file} does not exist.")
        return False

    with open(lfi_file, 'w') as output:
        command = ["gf", "lfi", input_file]
        subprocess.run(command, stdout=output)

    max_attempts = 10
    attempt = 0
    sleep_time = 5  # seconds

    while attempt < max_attempts:
        if os.path.exists(lfi_file) and os.path.getsize(lfi_file) > 0:
            logger.info(f"LFI URLs filtered and written to {lfi_file}")
            return True
        else:
            logger.info(f"Waiting for {lfi_file} to be created... Attempt {attempt + 1}/{max_attempts}")
            time.sleep(sleep_time)
            attempt += 1

    logger.error(f"Failed to create {lfi_file} after {max_attempts} attempts.")
    return False

def replace_fuzz(lfi_file):
    logger = setup_logger()
    updated_urls = set()

    with open(lfi_file, 'r') as file:
        urls = file.read().splitlines()

    for url in urls:
        # Check if URL contains a query string
        if '?' in url:
            base_url, query_string = url.split('?', 1)
            params = query_string.split('&')
            modified_params = [f"{param.split('=')[0]}=FUZZ" for param in params if '=' in param]
            new_url = f"{base_url}?{'&'.join(modified_params)}"
            updated_urls.add(new_url)
        else:
            # If there's no query string, just append "FUZZ" to the URL
            updated_urls.add(url + "FUZZ")

    with open(lfi_file, 'w') as file:
        for url in sorted(updated_urls):
            file.write(url + '\n')

    logger.info(f"FUZZ keyword replaced and duplicates removed in URLs in {lfi_file}")

def clean_ansi_sequences(input_string):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', input_string)

def run_ffuf(lfi_file, payloads_file):
    logger = setup_logger()
    results = []
    with open(lfi_file, 'r') as file:
        urls = file.read().splitlines()

    for url in urls:
        logger.info(f"Running FFUF on URL: {url}")
        print(f"Running FFUF on URL: {url}")

        command = ["ffuf", "-u", url, "-mr", "root:x", "-w", payloads_file, "-r"]  # Set lower rate for requests
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        try:
            # Adjust the timeout based on typical response time expectations
            stdout, stderr = process.communicate(timeout=180)  # Timeout set to 60 seconds

            for line in stdout.splitlines():
                cleaned_line = clean_ansi_sequences(line)
                if "[Status: 200" in cleaned_line:
                    path = cleaned_line.split(' ')[0]
                    if "200" in cleaned_line:
                        results.append({
                            "url": url.replace("FUZZ", path),
                            "response_status": "200",
                            "payload": path
                        })
                        logger.info(f"LFI detected at: {url} with payload {path}")
        except subprocess.TimeoutExpired:
            logger.warning(f"FFUF command for URL {url} timed out. This URL may be rate-limited or too slow.")
            process.kill()
            process.wait()  # Ensure the process is cleaned up before continuing
        except Exception as e:
            logger.error(f"An error occurred while running FFUF: {str(e)}")
        finally:
            if process.poll() is None:  # Check if the process is still running
                process.terminate()
                try:
                    process.wait(timeout=5)  # Wait for process to terminate
                except subprocess.TimeoutExpired:
                    logger.warning(f"Process for URL {url} could not be terminated properly and was killed.")
                    process.kill()

    return results

def lfi_scan(katana_dir, lfi_dir, payloads_file):
    logger = setup_logger()
    os.makedirs(lfi_dir, exist_ok=True)
    lfi_file_path = os.path.join(lfi_dir, 'urls.lfi')
    results_json_path = os.path.join(lfi_dir, 'lfi_results.json')
    all_results = []

    for file_path in glob.glob(os.path.join(katana_dir, '*')):
        logger.info(f"Processing file: {file_path}")
        if filter_lfi_urls(file_path, lfi_file_path):
            replace_fuzz(lfi_file_path)
            results = run_ffuf(lfi_file_path, payloads_file)
            all_results.extend(results)

    if all_results:
        with open(results_json_path, 'w') as file:
            json.dump(all_results, file, indent=4)
        logger.info(f"All LFI results saved to {results_json_path}")
    else:
        logger.info("No LFI vulnerabilities detected across all files.")

if __name__ == "__main__":
    katana_dir = "/mnt/d/flask-thesis/results/katana"
    lfi_dir = "/mnt/d/flask-thesis/results/lfi"
    payloads_file = "/opt/smalllfi.txt"
    lfi_scan(katana_dir, lfi_dir, payloads_file)
