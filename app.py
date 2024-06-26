import os
import subprocess
from flask import Flask, request, render_template, jsonify, redirect, url_for
from concurrent.futures import ThreadPoolExecutor, as_completed
from read_json import read_all_json_results
import json

app = Flask(__name__)

# Define subdirectories for scan results
subdirectories = [
    "directories",
    "hosts",
    "lfi",
    "nmap",
    "shodan",
    "sqli",
    "subdomains",
    "techstack",
    "xss",
    "katana",
]


# Route to delete data by running 'delete.py'
@app.route("/delete-data", methods=["POST"])
def delete_data():
    # Execute the delete.py script
    delete_script_path = "delete.py"
    if os.path.exists(delete_script_path):
        subprocess.run(["python3", delete_script_path], check=True)
    return redirect(url_for("index"))  # Redirect back to the main dashboard


# Function to fetch scan results and prepare them for rendering
def flatten_json(y, parent_key="", separator="_"):
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
                    items.extend(
                        flatten_json(item, f"{new_key}_{i}", separator).items()
                    )
                else:
                    items.append((f"{new_key}_{i}", item))
        else:
            items.append((new_key, v))
    return dict(items)

def process_subdomains_results(subdomains):
    formatted_data = []
    # Ensure subdomains is a list
    if isinstance(subdomains, list):
        for subdomain in subdomains:
            # Each subdomain is added to the list as a dictionary with key "Subdomain"
            formatted_data.append({"Subdomain": subdomain})
    return formatted_data

def process_hosts_results(hosts_data):
    formatted_data = []
    if 'online' in hosts_data:
        for host, details in hosts_data['online'].items():
            # Each online host entry contains the host and its status code
            formatted_data.append({
                "Host": host,
                "Status Code": details.get('status_code', 'N/A'),
                "Error": ""  # No error message for online hosts
            })

    if 'offline' in hosts_data:
        for host, details in hosts_data['offline'].items():
            # Each offline host entry contains the host and its error message
            formatted_data.append({
                "Host": host,
                "Status Code": "",  # No status code for offline hosts
                "Error": details.get('error', 'N/A')
            })

    return formatted_data


def process_nmap_results(nmap_results):
    formatted_data = []
    # Check if 'nmap_results' is a dictionary and contains necessary data
    if isinstance(nmap_results, dict) and 'host' in nmap_results and 'open_ports' in nmap_results:
        host = nmap_results.get('host', 'Unknown')  # Fallback to 'Unknown' if no host key
        open_ports = nmap_results.get('open_ports', [])  # Fallback to an empty list if no open_ports key

        for port_info in open_ports:
            if isinstance(port_info, dict):
                entry = {
                    "Host": host,
                    "Open Ports": port_info.get('port', 'N/A'),
                    "Protocol": port_info.get('protocol', 'N/A'),
                    "Service": port_info.get('service', 'N/A')
                }
                formatted_data.append(entry)
    return formatted_data

# Example of processing results with added safety checks
def process_directory_results(directory_results):
    formatted_data = []
    for host, entries in directory_results.items():
        if entries:  # Ensure there are entries to process
            for entry in entries:
                if isinstance(entry, dict):  # Ensure each entry is a dictionary
                    formatted_entry = {
                        "URL": entry.get("url", "N/A"),
                        "Status": entry.get("status", "N/A"),
                        "Redirect Location": entry.get("redirectlocation", "N/A"),
                        "FUZZ": entry.get("FUZZ", "N/A")
                    }
                    formatted_data.append(formatted_entry)
                else:
                    print("Error: Entry is not a dictionary")  # Log unexpected data types
        else:
            print("Notice: No entries found for", host)  # Log empty entries

    return formatted_data


def process_sqli_results(vulnerabilities_results):
    formatted_data = []
    # Check if 'vulnerabilities_results' is a list of dictionaries
    if isinstance(vulnerabilities_results, list):
        for result in vulnerabilities_results:
            if 'url' in result and isinstance(result.get('vulnerabilities', []), list):
                url = result['url']
                vulnerabilities = result['vulnerabilities']

                for vuln_info in vulnerabilities:
                    entry = {
                        "URL": url,
                        "Payload": vuln_info.get('payload', 'N/A'),
                        "Server OS": vuln_info.get('server_os', 'N/A'),
                        "DBMS": vuln_info.get('dbms', 'N/A'),
                        "DBMS Version": vuln_info.get('dbms_version', 'N/A')
                    }
                    formatted_data.append(entry)
    return formatted_data


def process_techstack_results(techstack_results):
    formatted_data = []
    for host, info in techstack_results.items():
        entry = {
            "Host": host,
            "Operating System": "",
            "OS Version": "",
            "Web Server": "",
            "WB Version": "",
            "Editor": "",
            "Editor Version": "",
            "Language": "",
            "Language Version": "",
            "Miscellaneous": "",
            "PaaS": "",
            "CDN": ""
        }
        if "Operating systems" in info:
            os_info = (
                info["Operating systems"][0]
                if isinstance(info["Operating systems"], list)
                else info["Operating systems"]
            )
            entry["Operating System"] = os_info.get("detail", "")
            entry["OS Version"] = os_info.get("version", "")

        if "Web servers" in info:
            ws_info = (
                info["Web servers"][0]
                if isinstance(info["Web servers"], list)
                else info["Web servers"]
            )
            entry["Web Server"] = ws_info.get("detail", "")
            entry["WB Version"] = ws_info.get("version", "")

        if "Editors" in info:
            editor_info = (
                info["Editors"][0]
                if isinstance(info["Editors"], list)
                else info["Editors"]
            )
            entry["Editor"] = editor_info.get("detail", "")
            entry["Editor Version"] = editor_info.get("version", "")

        if "Programming languages" in info:
            lang_info = (
                info["Programming languages"][0]
                if isinstance(info["Programming languages"], list)
                else info["Programming languages"]
            )
            entry["Language"] = lang_info.get("detail", "")
            entry["Language Version"] = lang_info.get("version", "")

        if "Miscellaneous" in info:
            misc_info = ", ".join(
                f"{item['detail']} (v{item['version']})" for item in info["Miscellaneous"]
            ) if info["Miscellaneous"] else ""
            entry["Miscellaneous"] = misc_info

        if "PaaS" in info:
            paas_info = ", ".join(
                f"{item['detail']} (v{item['version']})" for item in info["PaaS"]
            ) if info["PaaS"] else ""
            entry["PaaS"] = paas_info

        if "CDN" in info:
            cdn_info = ", ".join(
                f"{item['detail']} (v{item['version']})" for item in info["CDN"]
            ) if info["CDN"] else ""
            entry["CDN"] = cdn_info

        formatted_data.append(entry)
    return formatted_data



def read_results():
    raw_results = read_all_json_results(subdirectories)  # Get the raw results

    techstack_results = raw_results["techstack"]
    nmap_results = raw_results["nmap"]
    subdomain_results = raw_results["subdomains"]
    hosts_results = raw_results["hosts"]
    sqli_results = raw_results["sqli"]
    dir_results = raw_results["directories"]
    # flatten the techstack results based on the headers in the headingMappings
    #print("Techstack results:", techstack_results)

    flattened_techstack_results = process_techstack_results(techstack_results)
    flattened_nmap_results = process_nmap_results(nmap_results)
    flattened_subdomains_results = process_subdomains_results(subdomain_results)
    flattened_hosts_results = process_hosts_results(hosts_results)
    flattened_sqli_results = process_sqli_results(sqli_results)
    flattened_dir_results = process_directory_results(dir_results)
    #print()
    #print()
    #print("Processed techstack results:", flattened_techstack_results)
    #print("Proccessed Nmap results:", flattened_nmap_results)
    #print("Proccessed Subdomains results:", flattened_subdomains_results)
    #print()
    raw_results["techstack"] = flattened_techstack_results
    raw_results["nmap"] = flattened_nmap_results
    raw_results["subdomains"] = flattened_subdomains_results
    raw_results["hosts"] = flattened_hosts_results
    raw_results["sqli"] = flattened_sqli_results
    raw_results["directories"] = flattened_dir_results
    

    return raw_results

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
        ("Scan Common Ports", scan_common_ports, (target_domain, )),
        ("Find Subdomains", find_subdomains, (target_domain,)),
        (
            "Shodan Search",
            shodan_search,
            (
                SHODAN_API_TOKEN,
                target_domain,
            ),
        ),
    ]
    Phase_2 = [
        ("Run HTTPx", run_httpx, ("results/subdomains",)),
        ("katana", run_crawler, (target_domain,)),
    ]
    Phase_3 = [
        (
            "Read Subdomains and Run FFUF",
            read_subdomains_and_run_ffuf,
            (
                target_domain,
                "/mnt/d/flask-thesis/results/hosts",
                "/mnt/d/flask-thesis/test/test.txt",
                "/mnt/d/flask-thesis/results/directories",
            ),
        ),
        (
            "Run Tech Stack Detection",
            run_tech_stack_detection,
            ("results/hosts", "results/techstack"),
        ),
    ]
    Phase_4 = [
        (
            "Run LFI Scan",
            lfi_scan,
            ("results/katana", "results/lfi", "/opt/smalllfi.txt"),
        ),
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
        futures_to_task = {
            executor.submit(task[1], *task[2]): task[0] for task in tasks
        }

        for future in as_completed(futures_to_task):
            task_name = futures_to_task[future]
            try:
                # Process each task and handle exceptions
                future.result()
            except Exception as exc:
                print(f"Task '{task_name}' generated an exception: {exc}")


headingMappings = {
    "directories" : ["URL , status , FUZZ"],
    "hosts": ["Domain", "Status Code"],
    "lfi": ["URL", "Status Code", "Payload"],
    "nmap": ["Host", "Open Ports", "Protocol", "Service"],
    "shodan": ["IP Address", "Port", "Organization", "Operating System"],
    "sqli": ["URL", "Payload"],
    "techstack": [
        "Host",
        "Operating System",
        "OS Version",
        "Web Server",
        "WB Version",
        "Editor",
        "Editor Version",
        "Language",
        "Language Version",
    ],
    "xss": ["URL", "Payload"],
    "subdomains": ["Subdomain"],
}


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

    print("Scan results:", scan_results)

    for key, content_list in scan_results.items():
        if content_list and isinstance(content_list[0], dict):
            scan_results[key] = content_list
        else:
            scan_results[key] = []

    return render_template(
        "index.html", scan_results=scan_results, headings=headingMappings
    )


# Route to list JSON files
@app.route("/json-files", methods=["GET"])
def list_json_files():
    files = [f for f in os.listdir(".") if f.endswith(".json", "txt")]
    return jsonify(files=files)


# Route to get a specific JSON file
@app.route("/json-files/<filename>", methods=["GET"])
def get_json_file(filename):
    if not filename.endswith(".json"):
        filename += ".json"

    if os.path.exists(filename):
        with open(filename, "r") as file:
            data = json.load(file)
        return jsonify(data)
    else:
        return jsonify(error=f"File {filename} not found"), 404


# Start Flask app
if __name__ == "__main__":
    app.run(debug=True)
