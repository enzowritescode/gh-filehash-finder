import argparse
import requests
import os
import time
import hashlib
import sys

# Constants
GITHUB_API_URL = "https://api.github.com"

# Function to get the GitHub token
def get_github_token():
    return os.getenv('GH_TOKEN') or os.getenv('GITHUB_TOKEN')

# Function to handle GitHub API requests with rate limit handling
def github_api_request(url, headers):
    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers and response.headers['X-RateLimit-Remaining'] == '0':
            reset_time = int(response.headers['X-RateLimit-Reset'])
            sleep_time = max(0, reset_time - int(time.time()))
            print(f"Rate limit exceeded. Sleeping for {sleep_time} seconds.", file=sys.stderr)
            time.sleep(sleep_time)
        else:
            response.raise_for_status()
            return response

# Function to calculate SHA256 hash of a file
def calculate_sha256(file_content):
    if not isinstance(file_content, bytes):
        file_content = bytes(file_content)
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_content)
    return sha256_hash.hexdigest()

# Update download_file to handle NoneType cases
def download_file(url):
    token = get_github_token()
    headers = {'Authorization': f'token {token}'}
    try:
        response = github_api_request(url, headers)
        response.raise_for_status()
        return response.content
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"File not found: {url}", file=sys.stderr)
        else:
            raise
    return None

# Function to get the default branch of a repository
def get_default_branch(repo_full_name):
    token = get_github_token()
    headers = {'Authorization': f'token {token}'}
    repo_url = f"{GITHUB_API_URL}/repos/{repo_full_name}"
    response = github_api_request(repo_url, headers)
    return response.json().get('default_branch', 'master')

# Parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description='File Hash Finder')
    parser.add_argument('--org', required=True, help='GitHub organization name')
    parser.add_argument('--iocs', help='Path to the IOC file')
    parser.add_argument('--repo-type', choices=['public', 'private'], help='Type of repositories to scan (public or private). Omit for all repositories.')
    parser.add_argument('--file-name', help='Name of the file to search for')
    parser.add_argument('--hash', help='Expected SHA256 hash of the file')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--outfile', help='Path to the output markdown file')
    return parser.parse_args()

# Update search_github_files to use the correct branch or reference
def search_github_files(filename, org_name, repo_type=None):
    token = get_github_token()
    headers = {'Authorization': f'token {token}'}
    repo_type_query = f'+is:{repo_type}' if repo_type else ''
    search_url = f"{GITHUB_API_URL}/search/code?q=filename:{filename}+in:path+org:{org_name}{repo_type_query}"
    response = github_api_request(search_url, headers)
    items = response.json().get('items', [])
    for item in items:
        # Log repository details for debugging
        repo_full_name = item['repository']['full_name']
        file_path = item['path']
        print(f"Analyzing file - Repository: {repo_full_name}, Path: {file_path}", file=sys.stderr)
        # Fetch the default branch using the GitHub API
        branch_or_ref = get_default_branch(repo_full_name)
        item['raw_url'] = f"https://raw.githubusercontent.com/{repo_full_name}/{branch_or_ref}/{file_path}"
    return items

# Function to generate markdown report
def generate_markdown_report(findings):
    report_lines = ["| Repository | File Path |", "|------------|-----------|"]
    for repo, path in findings:
        report_lines.append(f"| {repo} | {path} |")
    return "\n".join(report_lines)

def generate_findings(ioc_data, org_name, repo_type, debug):
    findings = []
    # Main logic
    print(f"Searching in GitHub organization {org_name} with repo type {repo_type or 'all'}...", file=sys.stderr)
    for filename, expected_hash in ioc_data:
        print(f"Searching for {filename}...", file=sys.stderr)
        files = search_github_files(filename, org_name, repo_type)
        for file_info in files:
            file_url = file_info.get('raw_url')
            repo_name = file_info['repository']['full_name']
            if debug:
                print(f"Downloading {file_url}...", file=sys.stderr)
            file_content = download_file(file_url)
            if file_content is None:
                if debug:
                    print(f"Failed to download {filename} from {file_url}", file=sys.stderr)
                continue
            actual_hash = calculate_sha256(file_content)
            if actual_hash == expected_hash:
                print(f"Match found for {filename}: {file_url}", file=sys.stderr)
                findings.append((repo_name, file_info['path']))
            else:
                print(f"Hash mismatch for {filename}: {file_url}", file=sys.stderr)
    return findings

def read_ioc_file(ioc_file_path):
    with open(ioc_file_path, 'r') as file:
        return [line.strip().split() for line in file.readlines() if line.strip() and not line.startswith('#')]


def validate_arguments(args):
    if not args.iocs and (not args.file_name or not args.hash):
        print("Error: Either --iocs or both --file-name and --hash must be provided.", file=sys.stderr)
        sys.exit(1)


def main():
    args = parse_arguments()
    validate_arguments(args)
    org_name = args.org
    repo_type = args.repo_type
    debug = args.debug

    ioc_data = None
    if args.iocs:
        ioc_data = read_ioc_file(args.iocs)
        if not ioc_data:
            print("Error: The IOCs file is empty.", file=sys.stderr)
            return
    else:
        ioc_data = [(args.file_name, args.hash)]

    findings = generate_findings(ioc_data, org_name, repo_type, debug)

    print("Scan finished.", file=sys.stderr)
    if not findings:
        markdown_report = "No matches found!"
    else:
        markdown_report = generate_markdown_report(findings)

    if args.outfile:
        with open(args.outfile, 'w') as outfile:
            outfile.write(markdown_report)
        print(f"Markdown report written to {args.outfile}", file=sys.stderr)
    else:
        print(markdown_report, file=sys.stdout)

if __name__ == "__main__":
    main()
