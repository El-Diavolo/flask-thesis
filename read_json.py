import os
import json
from flask import current_app
import sys
from pathlib import Path
# Get the directory containing app.py
current_dir = Path(__file__).parent
# Get the parent directory (the directory above the current one)
parent_dir = current_dir.parent

# Add the parent directory to sys.path
sys.path.append(str(parent_dir))

def read_all_json_results(scan_directories):
    results = {}
    # Base path where scan directories are located
    base_path = os.path.join(parent_dir, 'flask-thesis/results')  # Update this path

    # Loop through each specified scan result directory
    for scan_dir in scan_directories:
        full_scan_path = os.path.join(base_path, scan_dir)
        scan_results = {}
        print(f"Looking in base path: {base_path}")
        if os.path.isdir(full_scan_path):
            print(f"Found directory: {full_scan_path}")
            # Loop through all JSON files in the current scan directory
            for filename in os.listdir(full_scan_path):
                if filename.endswith('.json'):
                    try:
                        with open(os.path.join(full_scan_path, filename), 'r') as json_file:
                            # Use the filename (without '.json') as the key for these results
                            result_key = filename[:-5]
                            scan_results[result_key] = json.load(json_file)
                    except Exception as e:
                        scan_results[result_key] = f'Failed to load results: {e}'
        else:
            print(f"Directory not found: {full_scan_path}")

        results[scan_dir] = scan_results
    
    return results
