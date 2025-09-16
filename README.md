# GitHub File Hash Finder

Scan for specific files (filename/hash) in your GitHub org

## Prerequisites

The script assumes you have a GitHub token in your environment, either `GH_TOKEN` or `GITHUB_TOKEN`

## Setup

```
git clone https://github.com/enzowritescode/gh-filehash-finder.git

cd gh-filehash-finder

# create python virtual env
python3 -m venv venv
source venv/bin/activate
pip install requests
```

## Usage

```
# run for all repos
python fhf.py --org YOUR_ORG --iocs iocs.txt > report.md

# run separate scans for public/private repos
python fhf.py --org YOUR_ORG --repo-type public --iocs iocs.txt > public_report.md
python fhf.py --org YOUR_ORG --repo-type private --iocs iocs.txt > private_report.md
```

## Sample IOC files

Sample files to be used for the `--iocs` flag are in `iocs/`

- `shai-hulud.txt`
	- `bundle.js` file from the Shai Hulud supply chain attack
