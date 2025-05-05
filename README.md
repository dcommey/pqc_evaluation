# PQC Performance Evaluation

## Overview
This project benchmarks post-quantum cryptographic (PQC) algorithms and generates figures and tables comparing performance across platforms (macOS, Ubuntu, and Raspberry Pi).

## Citation
This work is currently under review. Citation information will be added upon publication.

## Directory Structure
- **/src/**: Core implementation files
- **/scripts/**: Python scripts for data processing and analysis
- **/tests/**: Test files and test data
- **/vendor/**: Cloned dependencies (e.g., liboqs)

## Requirements
- Python 3.8+
- Python libraries: numpy, pandas, matplotlib, seaborn
- LaTeX (for generating tables)

## Setup
1. Clone the repository
2. Run `setup_mac.sh` (for macOS) or `setup_ubuntu.sh` (for Ubuntu)
3. Activate the virtual environment: `source venv/bin/activate`

## Usage
1. Run benchmarks: `python src/run_benchmarks.py`
2. Generate analysis: `python scripts/consolidated_analysis.py`

## License
This project is licensed under the MIT License.
