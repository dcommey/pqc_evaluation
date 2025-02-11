#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Set environment variables relative to project root
export LIBOQS_INCLUDE_DIR="${SCRIPT_DIR}/vendor/local/include"
export LIBOQS_LIB_DIR="${SCRIPT_DIR}/vendor/local/lib"
export LD_LIBRARY_PATH="${SCRIPT_DIR}/vendor/local/lib:$LD_LIBRARY_PATH"
export DYLD_LIBRARY_PATH="${SCRIPT_DIR}/vendor/local/lib:$DYLD_LIBRARY_PATH"

# Activate virtual environment if it exists
if [ -f "${SCRIPT_DIR}/venv/bin/activate" ]; then
    source "${SCRIPT_DIR}/venv/bin/activate"
fi

echo "Environment variables set for PQC evaluation"
