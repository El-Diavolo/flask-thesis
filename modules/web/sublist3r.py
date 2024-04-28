import subprocess
import os
import json
from pathlib import Path

def run_command(command, output_file):
    try:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"[+] Output saved to {output_file}")
            return True
        else:
            print(f"[!] No results found using {command[0]}.")
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error running {command[0]}: {e}")
        return False

def find_subdomains(domain, output_folder="results/subdomains/"):
    Path(output_folder).mkdir(parents=True, exist_ok=True)

    sublist3r_output_file = os.path.join(output_folder, f"sublist3r_{domain.replace('.', '_')}.txt")
    subfinder_output_file = os.path.join(output_folder, f"subfinder_{domain.replace('.', '_')}.txt")
    combined_output_file = os.path.join(output_folder, f"combined_{domain.replace('.', '_')}.txt")
    combined_json_output_file = os.path.join(output_folder, f"subdomains_{domain.replace('.', '_')}.json")

    subdomains = {domain}  # Start with the main domain included
    sublist3r_count = 0
    subfinder_count = 0

    # Run Sublist3r
    sublist3r_command = ["sublist3r", "-d", domain, "-o", sublist3r_output_file]
    if run_command(sublist3r_command, sublist3r_output_file):
        with open(sublist3r_output_file, 'r') as file:
            sublist3r_domains = set(line.strip() for line in file if line.strip())
            sublist3r_count = len(sublist3r_domains)
            subdomains.update(sublist3r_domains)

    # Run Subfinder
    subfinder_command = ["subfinder", "-d", domain, "-o", subfinder_output_file]
    if run_command(subfinder_command, subfinder_output_file):
        with open(subfinder_output_file, 'r') as file:
            subfinder_domains = set(line.strip() for line in file if line.strip())  # Corrected syntax
            subfinder_count = len(subfinder_domains)
            subdomains.update(subfinder_domains)


    # Save combined unique subdomains to a new text file
    with open(combined_output_file, 'w') as file:
        for subdomain in sorted(subdomains):
            file.write(subdomain + "\n")

    # Save combined unique subdomains to a JSON file
    with open(combined_json_output_file, 'w') as json_file:
        json.dump(list(sorted(subdomains)), json_file, indent=4)  # Convert to JSON

    print(f"[+] Sublist3r found {sublist3r_count} subdomains.")
    print(f"[+] Subfinder found {subfinder_count} subdomains.")
    print(f"[+] Combined unique subdomains: {len(subdomains)}")
    print(f"[+] Combined unique subdomains saved to {combined_output_file}")
    print(f"[+] Combined unique subdomains JSON saved to {combined_json_output_file}")

    # Clean up Sublist3r and Subfinder output files
    if os.path.exists(sublist3r_output_file):
        os.remove(sublist3r_output_file)
    if os.path.exists(subfinder_output_file):
        os.remove(subfinder_output_file)
    print("[+] Temporary files deleted.")

    return list(sorted(subdomains))  # Return the combined list


if __name__ == "__main__":
    domain = "example.com"
    find_subdomains(domain)
