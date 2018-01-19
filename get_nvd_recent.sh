#!/usr/bin/env bash

set -e
set -x

url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz'

curl -sL ${url} | gunzip - > nvdcve.json

echo "Successfully downloaded recent NVD data feed."
