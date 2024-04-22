import subprocess
import os

def setup_environment(output_dir):
    os.makedirs(output_dir, exist_ok=True)

def run_katana_scan(target_domain, output_dir):
    url = f"http://{target_domain}"
    output_file_path = os.path.join(output_dir, "katana_results.txt")
    command = ["katana", "-u", url, "-output", output_file_path]

    try:
        subprocess.run(command, check=True)
        print(f"Katana crawling completed for {url}, results saved to {output_file_path}")
    except subprocess.CalledProcessError as e:
        print(f"Katana failed for {url}: {str(e)}")
    return output_file_path

def run_gau_scan(target_domain, output_dir):
    output_file_path = os.path.join(output_dir, "gau_results.txt")
    command = ["gau", target_domain, "--o", output_file_path]

    try:
        subprocess.run(command, check=True)
        print(f"gau crawling completed for {target_domain}, results saved to {output_file_path}")
    except subprocess.CalledProcessError as e:
        print(f"gau failed for {target_domain}: {str(e)}")
    return output_file_path

def deduplicate_urls(katana_file, gau_file, output_file):
    command = ["uro", "-i", katana_file, "-i", gau_file, "-o", output_file]

    try:
        subprocess.run(command, check=True)
        print(f"URLs deduplicated and saved to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to deduplicate URLs: {str(e)}")

def run_crawler(target_domain):
    output_dir = "results/katana"
    setup_environment(output_dir)

    katana_output = run_katana_scan(target_domain, output_dir)
    gau_output = run_gau_scan(target_domain, output_dir)
    final_output = os.path.join(output_dir, "final_deduplicated_urls.txt")

    deduplicate_urls(katana_output, gau_output, final_output)

    # Remove intermediate files after deduplication
    os.remove(katana_output)
    os.remove(gau_output)
    print(f"Intermediate files removed, final deduplicated file kept at {final_output}")

if __name__ == "__main__":
    target_domain = "testphp.vulnweb.com"
    run_crawler(target_domain)
