import asyncio
import httpx
import json
import os

async def check_subdomain(client, subdomain, results):
    try:
        response = await client.get(f"http://{subdomain}")
        print(f"{subdomain} - {response.status_code}")
        results['online'][subdomain] = {'status_code': response.status_code}
    except Exception as e: 
        print(f"Error checking {subdomain}: {e}")
        results['offline'][subdomain] = {'error': str(e)}

async def run_checks(subdomains, batch_size=100):
    results = {'online': {}, 'offline': {}}
    timeout = 10.0
    
    for i in range(0, len(subdomains), batch_size):
        batch = subdomains[i:i + batch_size]
        async with httpx.AsyncClient(timeout=timeout) as client:
            tasks = [check_subdomain(client, subdomain, results) for subdomain in batch]
            await asyncio.gather(*tasks)
    return results


def get_subdomains_from_directory(subdomains_dir):
    all_subdomains = []
    for filename in os.listdir(subdomains_dir):
        if filename.endswith('.txt'):
            filepath = os.path.join(subdomains_dir, filename)
            with open(filepath, 'r') as file:
                subdomains = file.read().splitlines()
                all_subdomains.extend(subdomains)
    return all_subdomains

def run_httpx(subdomains_dir, results_dir='results/hosts'):
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)

    all_subdomains = get_subdomains_from_directory(subdomains_dir)
    results = asyncio.run(run_checks(all_subdomains))

    results_file_path = os.path.join(results_dir, "all_domains_httpx_results.json")
    
    with open(results_file_path, 'w') as json_file:
        json.dump(results, json_file, indent=4)
    
    print(f"HTTPx results saved to {results_file_path}")

if __name__ == "__main__":
    domain = "results/subdomains"
    run_httpx(domain)