# PQC Performance Evaluation

## Overview

This project provides a framework for benchmarking the performance of Post-Quantum Cryptography (PQC) algorithms, specifically Key Encapsulation Mechanisms (KEMs) and Digital Signature schemes, against classical counterparts (RSA, ECC). It facilitates cross-platform evaluation (tested on macOS, Ubuntu, Raspberry Pi) and generates consolidated analysis reports including figures and tables suitable for research publication. The focus is on metrics relevant to Consumer Electronics (CE) and resource-constrained environments, such as execution time and communication costs.

The benchmarking relies on the `liboqs` library for PQC implementations and the `cryptography` library for classical baselines. Analysis scripts process the raw benchmark data, handle algorithm name consolidation (e.g., Kyber -> ML-KEM), and produce structured outputs.

## Features

*   Benchmarks NIST PQC standards (ML-KEM, ML-DSA, Falcon, SPHINCS+) and other relevant candidates (BIKE, HQC, Classic McEliece, FrodoKEM, MAYO).
*   Includes classical baselines (RSA, ECDH, ECDSA, Ed25519).
*   Supports cross-platform execution (macOS, Ubuntu, Raspberry Pi tested).
*   Measures execution time (KeyGen, Encaps/Decaps, Sign/Verify) and communication sizes (Keys, Ciphertexts, Signatures).
*   Evaluates signature performance across varying message sizes (1KB to 1MB).

## Prerequisites

*   **System:**
    *   Python 3.8+
    *   A C compiler (GCC on Linux/RPi, Clang/Xcode Command Line Tools on macOS)
    *   CMake (often required for building `oqs-python`/`liboqs`)
    *   OpenSSL development libraries (e.g., `libssl-dev` on Debian/Ubuntu, usually included with Xcode Tools on macOS)
    *   Optional: A working LaTeX distribution (like TeX Live or MiKTeX) for generating PDF plots/tables with publication-quality fonts. If not installed, set `USE_TEX = False` in the analysis scripts.
*   **Python Packages:** Listed in `requirements.txt`. Install via pip. Key libraries include:
    *   `numpy`
    *   `pandas`
    *   `matplotlib`
    *   `seaborn`
    *   `oqs` (provides `liboqs` wrapper)
    *   `cryptography`

## Installation

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/dcommey/pqc_evaluation.git
    cd pqc_evaluation
    ```

2.  **Set up Python Environment (Recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3.  **Install Python Dependencies:**
    *(Ensure you have pip installed and updated: `python -m ensurepip --upgrade`)*
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: You might need to install system prerequisites like compilers, CMake, and OpenSSL headers before `oqs` and `cryptography` can be installed successfully.)*

4.  **Install LaTeX (Optional):** Follow instructions for your OS (e.g., [TeX Live](https://www.tug.org/texlive/), [MiKTeX](https://miktex.org/)).

## Usage

1.  **Run Benchmarks:**
    Use the `run_benchmarks.py` script. Specify the platform you are running on.
    ```bash
    # Example: Run full benchmarks on Ubuntu
    python scripts/run_benchmarks.py --platform ubuntu --iterations 1000

    # Example: Run quick test (10 iterations) on Raspberry Pi, skipping baseline
    python scripts/run_benchmarks.py --platform raspberry --quick-test --skip-baseline
    ```
    *   `--platform`: Required (choices: `macos`, `ubuntu`, `raspberry`).
    *   `--iterations`: Number of repetitions (default: 1000).
    *   `--skip-baseline`: Optional flag to skip classical algorithm benchmarks.
    *   `--skip-pqc`: Optional flag to skip PQC algorithm benchmarks.
    *   `--quick-test`: Optional flag to run only 10 iterations (for testing setup).
    *   Raw results are saved under `results/<platform_name>/<timestamp>/`.

2.  **Generate Consolidated Analysis:**
    After running benchmarks on one or more platforms, use `consolidated_analysis.py`. It automatically finds the *latest* run directory for each specified platform within the `--results-dir`.
    ```bash
    # Process results from the 'results/' directory
    python scripts/consolidated_analysis.py --results-dir results

    # Disable LaTeX rendering for plots/tables
    python scripts/consolidated_analysis.py --results-dir results --no-tex
    ```
    *   `--results-dir`: Base directory containing platform result folders (default: `results`).
    *   `--no-tex`: Use standard matplotlib fonts instead of LaTeX for rendering (useful if LaTeX is not installed).
    *   Output is saved to `results/consolidated_analysis_v2/`.

## Output Description

*   **Raw Benchmarks (`results/<platform>/<timestamp>/`):**
    *   `pqc/pqc_metrics.json`: Raw PQC results in JSON format.
    *   `baseline/baseline_metrics.json`: Raw classical results in JSON format.
    *   `raw_data/*.json`: Copies of the above.
    *   `experiment_config.json`: Records the parameters used for the benchmark run.
*   **Consolidated Analysis (`results/consolidated_analysis_v2/`):**
    *   `data/*.csv`: Processed and consolidated data used for plots/tables.
    *   `figures/*.pdf`: Generated performance comparison figures.
    *   `tables/*.tex`: Generated performance summary tables in LaTeX format.
*   **Appendix Analysis (`results/appendix_analysis/`):**
    *   `data/*.csv`: Processed data used for appendix analysis.
    *   `figures/*.pdf`: Detailed ratio plots.
    *   `tables/*.tex`: Detailed performance and ratio tables in LaTeX format.

## Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request.

## License

MIT

## Citation

If you use this framework or results in your research, please cite:
[link to publication will be added when available]
