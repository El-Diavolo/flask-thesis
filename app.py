import os
from flask import Flask, request, render_template
from concurrent.futures import ThreadPoolExecutor, as_completed
from read_json import read_all_json_results
import json

app = Flask(__name__)

# Define subdirectories for scan results
subdirectories = ["directories", "hosts", "lfi", "nmap", "shodan", "sqli", "subdomains", "techstack", "xss", "katana"]

# Function to fetch scan results and prepare them for rendering
def read_results():
    raw_results = read_all_json_results(subdirectories)  # Get the raw results
    refined_results = {}

    # Flatten or restructure the results for easier rendering
    for subdir, content_dict in raw_results.items():
        flattened_results = []
        for key, value in content_dict.items():
            # If it's a nested dictionary, convert to key-value pairs
            if isinstance(value, dict):
                flattened_results.append(f"{key}: {json.dumps(value, indent=2)}")
            elif isinstance(value, list):
                flattened_results.extend([f"{key}: {json.dumps(item, indent=2)}" for item in value])
            else:
                flattened_results.append(f"{key}: {str(value)}")
        
        refined_results[subdir] = flattened_results
    
    return refined_results
  # Use the read_json.py function

# Function to run scans based on selected phases
def run_scans(target_domain, phases):
    from modules.web import (
        find_subdomains,
        read_subdomains_and_run_ffuf,
        run_httpx,
        run_crawler,
        shodan_search,
        run_tech_stack_detection,
        run_xss,
        lfi_scan,
        sqli_scan,
    )
    from modules.network import scan_common_ports

    # Define task phases
    Phase_1 = [("Scan Common Ports", scan_common_ports, (target_domain,)), ("Find Subdomains", find_subdomains, (target_domain,))]
    Phase_2 = [("Run HTTPx", run_httpx, ("results/subdomains",)), ("katana", run_crawler, (target_domain,))]
    Phase_3 = [
        ("Read Subdomains and Run FFUF", read_subdomains_and_run_ffuf, (target_domain, "results/hosts", "test/testwordlist.txt", "results/directories")),
        ("Run Tech Stack Detection", run_tech_stack_detection, ("results/hosts", "results/techstack")),
    ]
    Phase_4 = [("Run LFI Scan", lfi_scan, ("results/katana", "results/lfi", "/opt/smalllfi.txt"))]
    Phase_5 = [("Run Xss Scan", run_xss, ())]
    Phase_6 = [("Run SQLI Scan", sqli_scan, (target_domain,))]

    # Dictionary of phases
    phases_dict = {
        "Phase 1": Phase_1,
        "Phase 2": Phase_2,
        "Phase 3": Phase_3,
        "Phase 4": Phase_4,
        "Phase 5": Phase_5,
        "Phase 6": Phase_6,
    }

    # Execute selected phases
    for phase in phases:
        execute_tasks(phases_dict[phase], f"{phase}: {phases_dict[phase][0][0]}")

# Function to execute tasks concurrently
def execute_tasks(tasks):
    with ThreadPoolExecutor() as executor:
        futures_to_task = {executor.submit(task[1], *task[2]): task[0]}
        for future in as_completed(futures_to_task):
            task_name = futures_to_task[future]
            try:
                future.result()
            except Exception as exc:
                print(f"'{task_name}' generated an exception: {exc}")

# Route for the main dashboard
@app.route("/", methods=["GET", "POST"])
def index():
    scan_results = read_results()  # Get content from all subdirectories
    if request.method == "POST":
        target_domain = request.form["target_domain"]
        selected_phases = request.form.getlist("phases")

        # Execute tasks based on selected phases
        if selected_phases:
            run_scans(target_domain, selected_phases)

        # Refresh results after executing scans
        scan_results = read_results()

    return render_template("index.html", scan_results=scan_results)

# Start Flask app
if __name__ == "__main__":
    app.run(debug=True)
