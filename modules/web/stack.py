import subprocess
import os
import json
import re

def run_tech_stack_detection(hosts_dir='results/hosts', output_dir='results/techstack'):
    os.makedirs(output_dir, exist_ok=True)

    for filename in os.listdir(hosts_dir):
        if filename.endswith('.json'):
            filepath = os.path.join(hosts_dir, filename)
            with open(filepath, 'r') as file:
                hosts_data = json.load(file)
                online_hosts = hosts_data.get('online', {})

                for host, details in online_hosts.items():
                    if details.get('status_code') in [200, 301]:
                        output_filename = f"{host.replace('https://', '').replace('http://', '').replace('/', '_')}_tech_stack.txt"
                        output_file = os.path.join(output_dir, output_filename)
                        command = ['wappy', '-u', host]  # Update your command as needed

                        try:
                            with open(output_file, 'w') as f:
                                subprocess.run(command, check=True, stdout=f, text=True)
                            print(f"Tech stack detection output for {host} saved to {output_file}")
                        except subprocess.CalledProcessError as e:
                            print(f"Error detecting tech stack for {host}: {e}")

    compile_tech_stacks_to_json(output_dir)

def compile_tech_stacks_to_json(output_dir):
    all_tech_stacks = {}

    for filename in os.listdir(output_dir):
        if filename.endswith('_tech_stack.txt'):
            filepath = os.path.join(output_dir, filename)
            with open(filepath, 'r') as file:
                text_output = file.read()
                host = filename.replace('_tech_stack.txt', '').replace('_', '/')
                tech_stack_data = parse_wappy_output_to_json(text_output)
                all_tech_stacks[host] = tech_stack_data
            os.remove(filepath)  # Optionally remove the .txt file

    compiled_results_file = os.path.join(output_dir, 'compiled_tech_stacks.json')
    with open(compiled_results_file, 'w') as file:
        json.dump(all_tech_stacks, file, indent=4)
    print(f"Compiled tech stack detection results saved to {compiled_results_file}")

def parse_wappy_output_to_json(text_output):

    tech_stack = {}
    for line in text_output.splitlines():
        match = re.match(r"^(.+?)\s*:\s*(.+?)\s*\[version:\s*(.*?)\]$", line)
        if match:
            technology, detail, version = match.groups()
            if technology not in tech_stack:
                tech_stack[technology] = []
            tech_stack[technology].append({'detail': detail, 'version': version or 'nil'})

    return tech_stack

if __name__ == "__main__":
    run_tech_stack_detection()
