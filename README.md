# GitHub File Hash Finder

Scan for specific files (filename/hash) in your GitHub organization. This tool is specifically designed to search for known Indicators of Compromise (IoCs) by identifying files with specific filenames and hashes, such as the `bundle.js` file from the Shai Hulud supply chain attack.

## Prerequisites

- A GitHub token set in your environment, either `GH_TOKEN` or `GITHUB_TOKEN`.
- Python 3.9 or higher.

## Setup

```
git clone https://github.com/enzowritescode/gh-filehash-finder.git

cd gh-filehash-finder

# create python virtual env
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Command-line Options

```
usage: fhf.py [-h] --org ORG [--iocs IOCS] [--repo-type {public,private}] [--file-name FILE_NAME] [--hash HASH] [--debug]
              [--outfile OUTFILE]

File Hash Finder

options:
  -h, --help            show this help message and exit
  --org ORG             GitHub organization name
  --iocs IOCS           Path to the IOC file
  --repo-type {public,private}
                        Type of repositories to scan (public or private). Omit for all repositories.
  --file-name FILE_NAME
                        Name of the file to search for
  --hash HASH           Expected SHA256 hash of the file
  --debug               Enable debug output
  --outfile OUTFILE     Path to the output markdown file
```

## Example Usage

```
# run for all repos
python fhf.py --org YOUR_ORG --iocs iocs.txt > report.md

# run separate scans for public/private repos
python fhf.py --org YOUR_ORG --repo-type public --iocs iocs.txt > public_report.md
python fhf.py --org YOUR_ORG --repo-type private --iocs iocs.txt > private_report.md

# run with specific file name and hash
python fhf.py --org YOUR_ORG --file-name FILENAME --hash HASH > report.md

# specify output file
python fhf.py --org YOUR_ORG --iocs iocs.txt --outfile report.md

# specify output file with file name and hash
python fhf.py --org YOUR_ORG --file-name FILENAME --hash HASH --outfile report.md
```

## Sample IOC files

Sample files to be used for the `--iocs` flag are in `iocs/`

- `shai-hulud.txt`
	- `bundle.js` file from the Shai Hulud supply chain attack
