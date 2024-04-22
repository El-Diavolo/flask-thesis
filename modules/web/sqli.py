import subprocess
import os
import json
import re
import logging

# Set up logging for debugging and progress monitoring
def setup_logger():
    logger = logging.getLogger("SQLI_Detection")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    return logger

# Run gau to collect URLs from the given domain
def run_gau(target_domain, output_file):
    command = ["gau", target_domain, "--o", output_file]
    logger = setup_logger()
    try:
        subprocess.run(command, check=True)
        logger.info(f"gau completed for {target_domain}, results saved to {output_file}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to run gau for {target_domain}: {str(e)}")

# Filter SQL injection-prone URLs using gf
def filter_sqli_urls(input_file, output_file):
    command = ["gf", "sqli", input_file]
    logger = setup_logger()
    with open(output_file, 'w') as outfile:
        subprocess.run(command, stdout=outfile)
        logger.info(f"Filtered SQLi URLs and written to {output_file}")

# Run sqlmap with specified options and save extracted details to JSON
def run_sqlmap(sqli_file, json_output):
    command = [
        "sqlmap",
        "-m", sqli_file,
        "--level", "5",
        "--risk", "3",
        "--batch",
        "--dbms", "mysql",
        "--tamper", "between",
        "--skip-static"
    ]
    logger = setup_logger()

    try:
        # Capture sqlmap output
        result = subprocess.run(command, check=True, capture_output=True, text=True)

        # Regex to extract SQL injection information
        sqli_pattern = re.compile(
            r"Parameter: (.*?)\s*\((.*?)\)\s+"
            r"(Type: .*?Payload:.*?)\s*--",  # Capture everything from Type to Payload until double hyphen
            re.DOTALL
        )

        # Extract URLs being tested
        url_pattern = re.compile(r"testing URL '(.*?)'")
        url_matches = url_pattern.findall(result.stdout)

        # Capture SQL injection information
        vulnerable_info = []
        for match in sqli_pattern.finditer(result.stdout):
            parameter = match.group(1).strip()
            http_method = match.group(2).strip()

            # Extract detailed SQLi information
            details = match.group(3)
            sql_type = re.search(r"Type: (.*?)\s+", details).group(1).strip()
            title = re.search(r"Title: (.*?)\s+", details).group(1).strip()
            payload = re.search(r"Payload: (.*?)\s+", details).group(1).strip()

            # Append all relevant information
            for url in url_matches:
                vulnerable_info.append({
                    "url": url,
                    "parameter": parameter,
                    "http_method": http_method,
                    "sql_injection_type": sql_type,
                    "title": title,
                    "payload": payload
                })

        # Save results to JSON
        with open(json_output, 'w') as json_file:
            json.dump(vulnerable_info, json_file, indent=4)

        logger.info(f"sqlmap results saved to {json_output}")

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to run sqlmap on {sqli_file}: {str(e)}")

# Main function to run gau, filter URLs, and execute sqlmap
def sqli_scan(target_domain):
    output_dir = "results/sqli"
    os.makedirs(output_dir, exist_ok=True)

    gau_file = os.path.join(output_dir, "fgau.txt")  # Output from gau
    sqli_file = os.path.join(output_dir, "sqli_filtered.txt")  # Filtered SQLi-prone URLs
    json_output = os.path.join(output_dir, "sqli_results.json")  # Final JSON output

    # Run gau, filter SQLi URLs, and execute sqlmap
    run_gau(target_domain, gau_file)
    filter_sqli_urls(gau_file, sqli_file)
    run_sqlmap(sqli_file, json_output)

# Entry point for the script
if __name__ == "__main__":
    target_domain = "testphp.vulnweb.com"
    sqli_scan(target_domain)
