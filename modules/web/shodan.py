import shodan
import json
import os

def filter_results(matches):
    """Extract and return filtered information from Shodan search results."""
    filtered_results = []
    for result in matches:
        filtered_result = {
            'ip': result.get('ip_str', 'n/a'),
            'ports': result.get('ports', []),
            'org': result.get('org', 'n/a'),
            'os': result.get('os', 'n/a'),
            # Include other relevant fields as necessary
        }
        # Optionally, include more complex fields if available
        if 'http' in result:
            filtered_result['http'] = {
                'server': result['http'].get('server', 'n/a'),
                'title': result['http'].get('title', 'n/a')
            }
        filtered_results.append(filtered_result)
    return filtered_results

def shodan_search(api_key, query, output_dir='results/shodan'):
    api = shodan.Shodan(api_key)
    os.makedirs(output_dir, exist_ok=True)
    output_file_path = os.path.join(output_dir, f"{query.replace(' ', '_')}_shodan_results.json")

    try:
        results = api.search(query)
        print(f"Results found: {results['total']}")
        
        # Filter the results to include only the relevant information
        filtered_results = filter_results(results['matches'])
        
        # Save the filtered results to a JSON file
        with open(output_file_path, 'w') as file:
            json.dump(filtered_results, file, indent=4)
        
        print(f"Filtered Shodan search results saved to {output_file_path}")
    except shodan.APIError as e:
        print(f"Error: {e}")