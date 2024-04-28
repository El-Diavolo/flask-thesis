import os
import subprocess
from flask import Flask, request, render_template, jsonify, redirect, url_for
from concurrent.futures import ThreadPoolExecutor, as_completed
from read_json import read_all_json_results
import json

app = Flask(__name__)

# Define subdirectories for scan results
subdirectories = ["directories", "hosts", "lfi", "nmap", "shodan", "sqli", "subdomains", "techstack", "xss", "katana"]

# Route to delete data by running 'delete.py'
@app.route("/delete-data", methods=["POST"])
def delete_data():
    # Execute the delete.py script
    delete_script_path = "delete.py"
    if os.path.exists(delete_script_path):
        subprocess.run(["python3", delete_script_path], check=True)
    return redirect(url_for("index"))  # Redirect back to the main dashboard

# Function to fetch scan results and prepare them for rendering
def flatten_json(y, parent_key='', separator='_'):
    """
    Recursively flattens nested JSON/dictionaries.
    """
    items = []
    for k, v in y.items():
        new_key = parent_key + separator + k if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_json(v, new_key, separator).items())
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    items.extend(flatten_json(item, f"{new_key}_{i}", separator).items())
                else:
                    items.append((f"{new_key}_{i}", item))
        else:
            items.append((new_key, v))
    return dict(items)


def read_results():
    raw_results = read_all_json_results(subdirectories)  # Get the raw results
    refined_results = {}

    for subdir, content_dict in raw_results.items():
        flattened_results = []
        for key, value in content_dict.items():
            if isinstance(value, dict):
                flattened_value = flatten_json(value)
                flattened_results.append(flattened_value)
            elif isinstance(value, list):
                # Flatten the list and ensure the key-value pairs are correctly formatted
                for item in value:
                    if isinstance(item, dict):
                        flattened_results.append(flatten_json(item))
                    else:
                        flattened_results.append({key: item})
            else:
                flattened_results.append({key: value})

        refined_results[subdir] = flattened_results
    
    print("Refined results:", refined_results)  # Debugging output
    
    return refined_results






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
    from dotenv import load_dotenv
    load_dotenv()
    SHODAN_API_TOKEN = os.getenv("SHODAN_API_TOKEN")

    # Define task phases
    Phase_1 = [
        ("Scan Common Ports", scan_common_ports, (target_domain,)),
        ("Find Subdomains", find_subdomains, (target_domain,)),
        ("Shodan Search", shodan_search, (SHODAN_API_TOKEN,target_domain,))
    ]
    Phase_2 = [
        ("Run HTTPx", run_httpx, ("results/subdomains",)),
        ("katana", run_crawler, (target_domain,)),
    ]
    Phase_3 = [
        ("Read Subdomains and Run FFUF", read_subdomains_and_run_ffuf, (target_domain, "results/hosts", "test/testwordlist.txt", "results/directories")),
        ("Run Tech Stack Detection", run_tech_stack_detection, ("results/hosts", "results/techstack")),
    ]
    Phase_4 = [
        ("Run LFI Scan", lfi_scan, ("results/katana", "results/lfi", "/opt/smalllfi.txt")),
    ]
    Phase_5 = [("Run XSS Scan", run_xss, ())]
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
        execute_tasks(phases_dict[phase])


def execute_tasks(tasks):
    # Ensure 'tasks' is a list of tuples
    if not isinstance(tasks, list):
        raise TypeError("Expected a list of tasks")

    with ThreadPoolExecutor() as executor:
        # Create a dictionary of futures to task names
        futures_to_task = {executor.submit(task[1], *task[2]): task[0] for task in tasks}

        for future in as_completed(futures_to_task):
            task_name = futures_to_task[future]
            try:
                # Process each task and handle exceptions
                future.result()
            except Exception as exc:
                print(f"Task '{task_name}' generated an exception: {exc}")


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


# Route to list JSON files
@app.route('/json-files', methods=['GET'])
def list_json_files():
    files = [f for f in os.listdir('.') if f.endswith('.json',"txt")]
    return jsonify(files=files)


# Route to get a specific JSON file
@app.route('/json-files/<filename>', methods=['GET'])
def get_json_file(filename):
    if not filename.endswith('.json'):
        filename += '.json'

    if os.path.exists(filename):
        with open(filename, 'r') as file:
            data = json.load(file)
        return jsonify(data)
    else:
        return jsonify(error=f"File {filename} not found"), 404


# Start Flask app
if __name__ == "__main__":
    app.run(debug=True)