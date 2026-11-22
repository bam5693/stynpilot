#!/bin/sh
# Run every test offline. No network, no root, no paid services.
set -eu
cd "$(dirname "$0")/.."
PYTHONPATH=src exec python3 -B -m unittest discover -s tests "$@"
