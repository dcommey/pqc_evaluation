#!/usr/bin/env python3
"""
Appendix analysis for post-quantum cryptography benchmarks.
Generates detailed per-algorithm tables and platform performance ratio plots/tables
using consolidated data. Assumes structure from consolidated_analysis.py.
Saves output to a separate 'appendix_analysis' directory.
"""

import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import matplotlib as mpl
import warnings
import re # For parsing algorithm names
# from adjustText import adjust_text # Import available if needed later

# Ignore potential warnings from plotting libraries
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=UserWarning)
# Ignore specific Pandas warnings about DataFrame fragmentation (often temporary)
warnings.filterwarnings('ignore', category=pd.errors.PerformanceWarning)


# --- Matplotlib Configuration ---
# Set to False if you don't have a LaTeX installation
USE_TEX = True # <<< Set this to False if you don't have LaTeX installed

plt.style.use(['seaborn-v0_8-paper'])
mpl.rcParams.update({
    'font.family': 'serif',
    'text.usetex': USE_TEX,
    'axes.titlesize': 10,
    'axes.labelsize': 9,
    'xtick.labelsize': 8,
    'ytick.labelsize': 8,
    'legend.fontsize': 8,
    'figure.titlesize': 11,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.1,
    # Font settings for LaTeX users
    'text.latex.preamble': r'\usepackage{amsmath} \usepackage{amsfonts} \usepackage{amssymb} \usepackage{siunitx}' if USE_TEX else '',
    'pgf.texsystem': 'pdflatex' if USE_TEX else None,
    'pgf.rcfonts': False if USE_TEX else None,
})

class AppendixAnalyzer:
    """
    Generates detailed appendix figures and tables using consolidated data.
    """

    # --- Configuration (matches ConsolidatedAnalyzer) ---
    PLATFORMS = ['macos', 'ubuntu', 'raspberry']
    RESOURCE_PLATFORM = 'raspberry'
    REFERENCE_PLATFORM = 'macos'
    OTHER_DESKTOP_PLATFORM = 'ubuntu' # Platform to compare against reference
    OUTPUT_SUBDIR = 'appendix_analysis' # New output directory name
    CONSOLIDATION_MAP = {
        'Kyber': 'ML-KEM',
        'CRYSTALS-Kyber': 'ML-KEM',
        'Dilithium': 'ML-DSA',
        'CRYSTALS-Dilithium': 'ML-DSA',
     }
    REVERSE_CONSOLIDATION_MAP = {v: k for k, v in CONSOLIDATION_MAP.items()}

    # Parameter mapping for non-standard to standard variants (MATCHES CONSOLIDATED_ANALYSIS)
    PARAMETER_MAP = {
        ('Kyber', '512'): ('ML-KEM', '512'),
        ('Kyber', '768'): ('ML-KEM', '768'),
        ('Kyber', '1024'): ('ML-KEM', '1024'),
        ('CRYSTALS-Kyber', '512'): ('ML-KEM', '512'),
        ('CRYSTALS-Kyber', '768'): ('ML-KEM', '768'),
        ('CRYSTALS-Kyber', '1024'): ('ML-KEM', '1024'),
        ('Dilithium', '2'): ('ML-DSA', '44'), 
        ('Dilithium', '3'): ('ML-DSA', '65'),
        ('Dilithium', '5'): ('ML-DSA', '87'),
        ('CRYSTALS-Dilithium', '2'): ('ML-DSA', '44'), 
        ('CRYSTALS-Dilithium', '3'): ('ML-DSA', '65'),
        ('CRYSTALS-Dilithium', '5'): ('ML-DSA', '87'),
    }

    # --- Initialization ---
    def __init__(self, results_base: Path):
        self.results_base = results_base
        self.output_dir = results_base / self.OUTPUT_SUBDIR # Use new subdir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / 'figures').mkdir(exist_ok=True)
        (self.output_dir / 'tables').mkdir(exist_ok=True)
        (self.output_dir / 'data').mkdir(exist_ok=True) # For processed data

        print("Loading raw results...")
        self.raw_results = self._load_all_results()

        # Check platform availability
        self.platforms_available = {p: p in self.raw_results for p in self.PLATFORMS}
        if not self.platforms_available[self.REFERENCE_PLATFORM]:
            raise ValueError(f"Reference platform '{self.REFERENCE_PLATFORM}' data is required but not found.")

        print("Preparing and consolidating data...")
        self.platform_data = self._prepare_and_consolidate_data()
        print("Data preparation complete.")

    # --- Data Loading ---
    def _load_all_results(self) -> dict:
        """Load raw results from all platforms."""
        results = {}
        for platform in self.PLATFORMS:
            platform_dir = self.results_base / platform
            if not platform_dir.exists():
                print(f"Warning: Platform directory not found: {platform_dir}")
                continue

            result_dirs = sorted([d for d in platform_dir.glob('*') if d.is_dir()], reverse=True)
            if not result_dirs:
                print(f"Warning: No result directories found in {platform_dir}")
                continue

            latest_dir = result_dirs[0] # Get the most recent directory
            print(f"Loading {platform} results from {latest_dir}")

            platform_results = {}
            try:
                # Load PQC results
                pqc_file = latest_dir / 'pqc' / 'pqc_metrics.json'
                if not pqc_file.exists():
                     print(f"Warning: PQC results file not found in {latest_dir}")
                     platform_results['pqc'] = {'results': {'kems': {}, 'signatures': {}}}
                else:
                    with open(pqc_file) as f:
                        platform_results['pqc'] = json.load(f)

                # Load baseline results
                baseline_file = latest_dir / 'baseline' / 'baseline_metrics.json'
                if not baseline_file.exists():
                    print(f"Warning: Baseline results file not found in {latest_dir}")
                    platform_results['baseline'] = {'results': {'kems': {}, 'signatures': {}}}
                else:
                    with open(baseline_file) as f:
                        platform_results['baseline'] = json.load(f)

                results[platform] = platform_results

            except Exception as e:
                print(f"Error loading {platform} results from {latest_dir}: {str(e)}")
        return results

    # --- Data Preparation and Consolidation ---
    def _get_algorithm_parts(self, name: str, apply_base_std: bool = True) -> tuple[str, str]:
        """Extract base name and parameters (improved).
        
        Args:
            name: The algorithm name string.
            apply_base_std: If True, applies base name standardization (e.g., Kyber->ML-KEM).
                          If False, returns the raw parsed base name.
        """
        # (Using the same robust pattern matching as consolidated_analysis.py)
        patterns = [
             r"^(ML-KEM|ML-DSA)-(\d+)",
             r"^(Kyber|Dilithium)(\d+)",
             r"^(Falcon(?:-padded)?)-(\d+)",
             r"([a-zA-Z\+\-]+[a-zA-Z]+)-([\w\-]+)",
             r"^(RSA|ECDSA|EdDSA|Ed25519)-?(\d+)?",
             r"^([a-zA-Z\+]+)",
        ]
        for pattern in patterns:
             match = re.match(pattern, name)
             if match:
                 base = match.group(1)
                 params = match.group(2) if len(match.groups()) > 1 and match.group(2) else ''

                 # Apply specific cleanups first 
                 if base == 'sntrup': base = 'NTRU-Prime'
                 if base == 'Classic-McEliece' and params: params = params.replace('f', '')
                 if base == 'Ed25519': 
                      base = 'EdDSA' 
                      params = '256' if not params else params

                 # --- Conditionally Apply Base Standardization --- 
                 if apply_base_std:
                     if base == 'Kyber': base = 'ML-KEM'
                     if base == 'Dilithium': base = 'ML-DSA'
                     if base.startswith('CRYSTALS-'):
                         if 'Kyber' in base: base = 'ML-KEM'
                         elif 'Dilithium' in base: base = 'ML-DSA'

                 return base, params
                 
        # Fallback
        print(f"Warning: Could not parse algorithm name: {name}")
        return name, ''

    def _prepare_and_consolidate_data(self) -> dict:
        """Prepare DataFrames for analysis, consolidating duplicate algorithms."""
        all_platform_data = {'kem': [], 'sig': []}
        print("  Loading initial data...")
        # (Load data - same logic as consolidated_analysis.py)
        for platform, results in self.raw_results.items():
            for name, data in results.get('pqc', {}).get('results', {}).get('kems', {}).items():
                if 'statistics' not in data or not data['statistics']: continue
                record = self._extract_kem_record(platform, name, data, 'Post-Quantum')
                if record: all_platform_data['kem'].append(record)
            for name, data in results.get('baseline', {}).get('results', {}).get('kems', {}).items():
                 if 'statistics' not in data or not data['statistics']: continue
                 record = self._extract_kem_record(platform, name, data, 'Classical')
                 if record: all_platform_data['kem'].append(record)
            for name, data in results.get('pqc', {}).get('results', {}).get('signatures', {}).items():
                if 'statistics' not in data or not data['statistics']: continue
                records = self._extract_sig_records(platform, name, data, 'Post-Quantum')
                all_platform_data['sig'].extend(records)
            for name, data in results.get('baseline', {}).get('results', {}).get('signatures', {}).items():
                 if 'statistics' not in data or not data['statistics']: continue
                 records = self._extract_sig_records(platform, name, data, 'Classical')
                 all_platform_data['sig'].extend(records)

        if not all_platform_data['kem'] and not all_platform_data['sig']:
             print("Error: No valid data loaded from any platform.")
             return {'kem': pd.DataFrame(), 'sig': pd.DataFrame()}

        print("  Converting to DataFrames...")
        kem_df = pd.DataFrame(all_platform_data['kem']) if all_platform_data['kem'] else pd.DataFrame()
        sig_df = pd.DataFrame(all_platform_data['sig']) if all_platform_data['sig'] else pd.DataFrame()

        print("  Applying initial standardization and parameter mapping...")
        for df in [kem_df, sig_df]:
            if df.empty: continue
            df['Original Algorithm'] = df['Algorithm']
            
            # Step 1: Dual Parsing
            raw_parts = df['Algorithm'].apply(lambda x: pd.Series(self._get_algorithm_parts(x, apply_base_std=False), 
                                                                  index=['Raw Base Name', 'Raw Params']))
            std_base_parts = df['Algorithm'].apply(lambda x: pd.Series(self._get_algorithm_parts(x, apply_base_std=True), 
                                                                        index=['Initial Std Base Name', 'Initial Params']))
            df['Raw Base Name'] = raw_parts['Raw Base Name']
            df['Raw Params'] = raw_parts['Raw Params']
            df['Initial Std Base Name'] = std_base_parts['Initial Std Base Name']
            df['Initial Params'] = std_base_parts['Initial Params']

            # Step 2: Determine Final Standard Name/Params and Flag
            standard_tuples = []
            for index, row in df.iterrows():
                raw_base = row['Raw Base Name']
                raw_params = row['Raw Params']
                raw_tuple = (raw_base, raw_params)
                original_algo_name = row['Original Algorithm']
                initial_std_base = row['Initial Std Base Name'] 

                mapped_std_tuple = self.PARAMETER_MAP.get(raw_tuple)
                final_std_base = initial_std_base
                final_std_params = row['Initial Params']
                is_original_standard = True

                if mapped_std_tuple: 
                    final_std_base, final_std_params = mapped_std_tuple
                    is_original_standard = False
                else:
                    if initial_std_base != raw_base:
                        is_original_standard = False
                
                standard_tuples.append((final_std_base, final_std_params, is_original_standard))
            
            standard_info_df = pd.DataFrame(standard_tuples, index=df.index, columns=['Std Base Name', 'Std Params', 'Is Original Name Standard'])
            df['Std Base Name'] = standard_info_df['Std Base Name']
            df['Std Params'] = standard_info_df['Std Params']
            df['Is Original Name Standard'] = standard_info_df['Is Original Name Standard']

        print("  Consolidating algorithm entries based on standardized names/params...")
        consolidated_kem_df = self._consolidate_df(kem_df, base_col='Std Base Name', params_col='Std Params', standard_flag_col='Is Original Name Standard')
        consolidated_sig_df = self._consolidate_df(sig_df, base_col='Std Base Name', params_col='Std Params', standard_flag_col='Is Original Name Standard')

        print("  Finalizing algorithm names and families...")
        for df in [consolidated_kem_df, consolidated_sig_df]:
            if df.empty: continue
            # Step 3: Reconstruct final Algorithm name
            df['Algorithm'] = df.apply(lambda row: f"{row['Std Base Name']}-{row['Std Params']}" if row['Std Params'] else row['Std Base Name'], axis=1)
            
            # Assign Family based on Standard Base Name
            df['Family'] = df['Std Base Name']
            # Apply family standardization rules (including corrected SPHINCS+)
            df.loc[df['Family'].isin(['Ed', 'Ed25519']), 'Family'] = 'EdDSA'
            df.loc[df['Family'].isin(['BIKE', 'HQC', 'Classic-McEliece']), 'Family'] = 'Code'
            df.loc[df['Family'].str.startswith('SPHINCS+', na=False), 'Family'] = 'Hash' # Correct SPHINCS+ grouping
            df.loc[df['Family'].isin(['MAYO', 'Rainbow']), 'Family'] = 'Multivariate'
            df.loc[df['Family'].str.contains('cross', case=False, na=False), 'Family'] = 'RSDP'
            # Keep specific families distinct if needed (e.g., Falcon, FrodoKEM)
            df.loc[df['Family'] == 'Falcon', 'Family'] = 'Falcon'
            df.loc[df['Family'] == 'FrodoKEM', 'Family'] = 'FrodoKEM'
            df.loc[df['Family'] == 'NTRU-Prime', 'Family'] = 'NTRU-Prime'
            
            # Step 4: Drop intermediate columns
            cols_to_drop = ['Original Algorithm', 'Raw Base Name', 'Raw Params',
                            'Initial Std Base Name', 'Initial Params', 
                            'Std Base Name', 'Std Params', 'Is Original Name Standard']
            df.drop(columns=[col for col in cols_to_drop if col in df.columns], inplace=True)

        print("  Saving processed data for appendix...") # Indicate appendix save
        if not consolidated_kem_df.empty:
             consolidated_kem_df.to_csv(self.output_dir / 'data' / 'appendix_consolidated_kem_data.csv', index=False)
        if not consolidated_sig_df.empty:
             consolidated_sig_df.to_csv(self.output_dir / 'data' / 'appendix_consolidated_sig_data.csv', index=False)

        return {'kem': consolidated_kem_df, 'sig': consolidated_sig_df}

    def _extract_kem_record(self, platform: str, name: str, data: dict, type_: str) -> dict | None:
        """Helper to extract a single KEM record, with error checking."""
        try:
            stats = data['statistics']
            sizes = data['sizes']
            details = data.get('algorithm_details', {})
            level = self._get_classical_security_level(name) if type_ == 'Classical' else details.get('claimed_nist_level', 0)
            required_stats = ['key_generation', 'encapsulation', 'decapsulation']
            required_sizes = ['public_key', 'ciphertext', 'shared_secret']
            if not all(k in stats for k in required_stats) or not all(s in sizes for s in required_sizes): return None
            if not stats['key_generation'] or not stats['encapsulation'] or not stats['decapsulation']: return None
            return {
                'Platform': platform.upper(), 'Algorithm': name, 'Type': type_,
                'Security Level': level if level is not None else 0,
                'Key Generation (ms)': stats['key_generation'].get('mean_ms', 0),
                'Encapsulation (ms)': stats['encapsulation'].get('mean_ms', 0),
                'Decapsulation (ms)': stats['decapsulation'].get('mean_ms', 0),
                'Public Key Size (bytes)': sizes.get('public_key', 0),
                'Ciphertext Size (bytes)': sizes.get('ciphertext', 0),
                'Shared Secret Size (bytes)': sizes.get('shared_secret', 0),
                'Key Gen Std (ms)': stats['key_generation'].get('std_ms', 0),
                'Encap Std (ms)': stats['encapsulation'].get('std_ms', 0),
                'Decap Std (ms)': stats['decapsulation'].get('std_ms', 0),
            }
        except Exception: return None

    def _extract_sig_records(self, platform: str, name: str, data: dict, type_: str) -> list:
        """Helper to extract signature records, with error checking."""
        records = []
        try:
            stats = data['statistics']
            sizes = data['sizes']
            details = data.get('algorithm_details', {})
            level = self._get_classical_security_level(name) if type_ == 'Classical' else details.get('claimed_nist_level', 0)
            required_stats = ['key_generation', 'signing', 'verification']
            required_sizes = ['public_key']
            if not all(k in stats for k in required_stats) or not all(s in sizes for s in required_sizes): return []
            if not stats['key_generation'] or not stats['signing'] or not stats['verification']: return []
            base_record = {
                'Platform': platform.upper(), 'Algorithm': name, 'Type': type_,
                'Security Level': level if level is not None else 0,
                'Key Generation (ms)': stats['key_generation'].get('mean_ms', 0),
                'Key Gen Std (ms)': stats['key_generation'].get('std_ms', 0),
                'Public Key Size (bytes)': sizes.get('public_key', 0),
            }
            for msg_size_str, sign_stats in stats.get('signing', {}).items():
                msg_size = int(msg_size_str)
                sig_size_key = f'signature_{msg_size}'
                verify_stats = stats.get('verification', {}).get(msg_size_str)
                if not verify_stats or sig_size_key not in sizes: continue
                record = base_record.copy()
                record.update({
                    'Message Size (bytes)': msg_size,
                    'Signing (ms)': sign_stats.get('mean_ms', 0),
                    'Sign Std (ms)': sign_stats.get('std_ms', 0),
                    'Verification (ms)': verify_stats.get('mean_ms', 0),
                    'Verify Std (ms)': verify_stats.get('std_ms', 0),
                    'Signature Size (bytes)': sizes.get(sig_size_key, 0),
                })
                records.append(record)
        except Exception: return []
        return records

    def _consolidate_df(self, df: pd.DataFrame, base_col: str, params_col: str, standard_flag_col: str) -> pd.DataFrame:
        """Consolidates duplicate algorithms in a DataFrame, prioritizing standard names.

        Args:
            df: The DataFrame to consolidate.
            base_col: The name of the column containing the standardized base algorithm name.
            params_col: The name of the column containing the standardized parameters.
            standard_flag_col: The name of the column indicating if the original name was standard.
        """
        if df.empty:
            print("Skipping consolidation for empty DataFrame.")
            return df

        # Ensure necessary columns exist
        required_cols = ['Platform', base_col, params_col, standard_flag_col, 'Algorithm'] # Algorithm needed for debug prints
        if not all(col in df.columns for col in required_cols):
            print(f"Warning: Consolidation skipped. Missing required columns: {required_cols} in DataFrame with columns {df.columns}")
            return df

        indices_to_drop = set()
        processed_groups = set()
        
        # Define the columns to group by for identifying duplicates
        group_cols = ['Platform', base_col, params_col]
        if 'Message Size (bytes)' in df.columns:
            group_cols.append('Message Size (bytes)')

        print(f"Consolidating based on groups: {group_cols}")
        # Group by Platform and the *standardized* Base Name and Params
        for group_key, group in df.groupby(group_cols):
            if len(group) <= 1:
                continue # No duplicates in this group
                
            if group_key in processed_groups:
                continue

            # Check if this group contains entries that were originally standard AND non-standard
            non_standard_entries = group[~group[standard_flag_col]]
            standard_entries = group[group[standard_flag_col]]

            # If we have both standard and non-standard originals mapping to the SAME Std Base/Params group,
            # drop the ones that originated from non-standard names.
            if not standard_entries.empty and not non_standard_entries.empty:
                # Debug print can be added here if needed, like in consolidated_analysis
                indices_to_drop.update(non_standard_entries.index)
                
            processed_groups.add(group_key)

        if indices_to_drop:
            print(f"  Identified {len(indices_to_drop)} entries originating from non-standard names to drop.")
            consolidated_df = df.drop(list(indices_to_drop)).reset_index(drop=True)
            print(f"  DataFrame shape after consolidation: {consolidated_df.shape}")
            return consolidated_df
        else:
            print("  No non-standard duplicates found to drop.")
            return df # Return original df if no changes made

    def _get_classical_security_level(self, name: str) -> int:
        """Estimate NIST security level for classical algorithms (improved)."""
        # (Using the same logic as consolidated_analysis.py)
        name_lower = name.lower(); match = re.search(r'(\d+)$', name)
        if not match: return 1 if 'ed25519' in name_lower else 0
        key_size = int(match.group(1))
        if 'rsa' in name_lower:
            if key_size >= 15360: return 5;
            if key_size >= 7680: return 4;
            if key_size >= 3072: return 3;
            if key_size >= 2048: return 1;
        elif 'ecdh' in name_lower or 'ecdsa' in name_lower:
            if key_size >= 512: return 5;
            if key_size >= 384: return 3;
            if key_size >= 256: return 1;
        return 0

    # --- Enhanced LaTeX Table Formatting ---
    def _consolidated_df_to_latex(self, df: pd.DataFrame, caption: str, label: str, **kwargs) -> str:
        """Formats a DataFrame to LaTeX with booktabs style."""
        # (Using the same robust logic as consolidated_analysis.py)
        latex_kwargs = { 'index': False, 'escape': False, 'longtable': True, 'caption': caption,
                         'label': label, 'column_format': None, 'float_format': '%.2f', 'na_rep': '-' }
        latex_kwargs.update(kwargs)
        if latex_kwargs['column_format'] is None:
            num_cols = len(df.columns); latex_kwargs['column_format'] = 'l' + 'r' * (num_cols -1) if num_cols > 0 else 'l'
        try:
            latex_str = df.to_latex(**latex_kwargs)
        except Exception as e:
            print(f"Error during initial to_latex call for {label}: {e}")
            return f"% Error generating LaTeX for table {label}"
        lines = latex_str.splitlines()
        try:
            begin_lt_index = -1; header_line_index = -1; midrule_inserted = False
            for i, line in enumerate(lines):
                if '\\begin{longtable}' in line: begin_lt_index = i
                if begin_lt_index != -1 and header_line_index == -1 and not line.strip().startswith('\\') and line.strip():
                     header_line_index = i
                     toprule_pos = i
                     for j in range(i - 1, begin_lt_index, -1):
                         if '{' in lines[j] and '}' in lines[j]: toprule_pos = j + 1; break
                     lines.insert(toprule_pos, '\\toprule'); header_line_index += 1
                if header_line_index != -1 and not midrule_inserted and line.strip() == '\\midrule': midrule_inserted = True
                if header_line_index != -1 and not midrule_inserted and ('\\endfirsthead' in line or '\\endhead' in line):
                    lines.insert(i + 1, '\\midrule'); midrule_inserted = True
            if header_line_index != -1 and not midrule_inserted: lines.insert(header_line_index + 1, '\\midrule')
            end_lt_index = -1
            for i in range(len(lines) - 1, -1, -1):
                if '\\end{longtable}' in lines[i]: end_lt_index = i; break
            if end_lt_index != -1: lines.insert(end_lt_index, '\\bottomrule')
            else: print(f"Warning: Could not find end{{longtable}} for table '{label}'.")
        except Exception as e:
             print(f"Error adding booktabs rules for {label}: {e}"); return latex_str
        return '\n'.join(lines)


    # --- Appendix Analysis Functions ---

    def generate_detailed_performance_tables(self):
        """Generate detailed per-algorithm performance tables for the appendix."""
        print("  Generating detailed performance tables...")
        if not self.platforms_available[self.REFERENCE_PLATFORM]:
            print("  Skipping detailed tables: Reference platform data unavailable.")
            return

        ref_platform_upper = self.REFERENCE_PLATFORM.upper()
        kem_data = self.platform_data['kem'][self.platform_data['kem']['Platform'] == ref_platform_upper]
        sig_data = self.platform_data['sig'][self.platform_data['sig']['Platform'] == ref_platform_upper]

        # KEM Detailed Table
        if not kem_data.empty:
            kem_cols_detail = [
                'Algorithm', 'Family', 'Type', 'Security Level',
                'Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)',
                'Public Key Size (bytes)', 'Ciphertext Size (bytes)', 'Shared Secret Size (bytes)'
            ]
            # Select and sort
            kem_detail_df = kem_data[kem_cols_detail].sort_values(
                by=['Type', 'Family', 'Security Level', 'Algorithm'], ascending=[False, True, True, True] # PQC first
            ).reset_index(drop=True)
            # Format numbers
            for col in ['Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)']:
                 if col in kem_detail_df: kem_detail_df[col] = kem_detail_df[col].map('{:.2f}'.format)
            for col in ['Public Key Size (bytes)', 'Ciphertext Size (bytes)', 'Shared Secret Size (bytes)']:
                 if col in kem_detail_df: kem_detail_df[col] = kem_detail_df[col].map('{:,}'.format) # Add commas

            tex_path = self.output_dir / 'tables' / 'appendix_kem_detailed_performance.tex'
            csv_path = self.output_dir / 'tables' / 'appendix_kem_detailed_performance.csv'
            with open(tex_path, 'w') as f:
                f.write(self._consolidated_df_to_latex(
                    kem_detail_df,
                    caption=f'Detailed KEM Performance and Size Metrics ({ref_platform_upper})',
                    label='tab:appendix_kem_detailed',
                    column_format='l'*4 + 'r'*6 # Adjust alignment
                ))
            kem_detail_df.to_csv(csv_path, index=False) # Save CSV (formatting already applied)

        # Signature Detailed Table
        if not sig_data.empty:
            # Pivot table
            try:
                sig_pivot = pd.pivot_table(
                    sig_data,
                    index=['Algorithm', 'Family', 'Type', 'Security Level', 'Key Generation (ms)', 'Public Key Size (bytes)'],
                    columns='Message Size (bytes)',
                    values=['Signing (ms)', 'Verification (ms)', 'Signature Size (bytes)']
                )
                # Flatten MultiIndex columns
                sig_pivot.columns = [f"{metric} ({int(size/1024)}KB)" if size>=1024 else f"{metric} ({size}B)"
                                     for metric, size in sig_pivot.columns]
                sig_detail_df = sig_pivot.reset_index().sort_values(
                     by=['Type', 'Family', 'Security Level', 'Algorithm'], ascending=[False, True, True, True]
                )

                # Format numbers
                perf_cols = [col for col in sig_detail_df.columns if '(ms)' in col]
                size_cols = [col for col in sig_detail_df.columns if '(bytes)' in col or '(B)' in col or '(KB)' in col]
                for col in perf_cols:
                     if col in sig_detail_df: sig_detail_df[col] = sig_detail_df[col].map('{:.2f}'.format)
                for col in size_cols:
                      if col in sig_detail_df and pd.api.types.is_numeric_dtype(sig_detail_df[col]):
                          sig_detail_df[col] = sig_detail_df[col].map('{:,.0f}'.format)

                # Define column format
                num_cols = len(sig_detail_df.columns)
                col_format = 'l'*4 + 'r'*(num_cols-4) # llllrrrr...

                tex_path = self.output_dir / 'tables' / 'appendix_sig_detailed_performance.tex'
                csv_path = self.output_dir / 'tables' / 'appendix_sig_detailed_performance.csv'
                with open(tex_path, 'w') as f:
                    f.write(self._consolidated_df_to_latex(
                        sig_detail_df,
                        caption=f'Detailed Signature Performance and Size Metrics by Message Size ({ref_platform_upper})',
                        label='tab:appendix_sig_detailed',
                        column_format=col_format,
                        float_format='%s' # Use pre-formatted strings
                    ))
                sig_detail_df.to_csv(csv_path, index=False) # Save CSV (formatting already applied)
            except Exception as e:
                 print(f"Warning: Could not generate detailed signature table: {e}")


    def generate_platform_ratio_analysis(self):
        """Generate platform performance ratio/slowdown plots and tables."""
        print("  Generating platform ratio analysis figures and tables...")

        ref_platform = self.REFERENCE_PLATFORM
        res_platform = self.RESOURCE_PLATFORM
        other_desk = self.OTHER_DESKTOP_PLATFORM

        if not self.platforms_available[ref_platform]:
             print(f"  Skipping ratio analysis: Reference platform {ref_platform} data missing.")
             return

        ref_upper = ref_platform.upper()
        kem_ref = self.platform_data['kem'][self.platform_data['kem']['Platform'] == ref_upper]
        sig_ref = self.platform_data['sig'][self.platform_data['sig']['Platform'] == ref_upper]

        ratio_dfs = {'kem': [], 'sig': []}
        platforms_to_compare = [p for p in [res_platform, other_desk] if self.platforms_available[p]]

        for plat in platforms_to_compare:
             plat_upper = plat.upper()
             print(f"    Calculating ratios for {plat_upper} vs {ref_upper}...")
             kem_plat = self.platform_data['kem'][self.platform_data['kem']['Platform'] == plat_upper]
             sig_plat = self.platform_data['sig'][self.platform_data['sig']['Platform'] == plat_upper]

             # Calculate KEM Ratios
             if not kem_ref.empty and not kem_plat.empty:
                 try:
                     merged_kem = pd.merge(
                         kem_ref[['Algorithm', 'Family', 'Type', 'Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)']],
                         kem_plat[['Algorithm', 'Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)']],
                         on='Algorithm', suffixes=('_ref', '_plat'), how='inner' # Ensure match
                     )
                     if not merged_kem.empty:
                          for op in ['Key Generation', 'Encapsulation', 'Decapsulation']:
                              time_ref = f'{op} (ms)_ref'; time_plat = f'{op} (ms)_plat'
                              mask = (merged_kem[time_ref] > 1e-9) & (merged_kem[time_plat].notna()) # Add notna check
                              merged_kem[f'{op} Ratio'] = np.nan
                              merged_kem.loc[mask, f'{op} Ratio'] = merged_kem.loc[mask, time_plat] / merged_kem.loc[mask, time_ref]
                          merged_kem['Compare Platform'] = plat_upper
                          ratio_dfs['kem'].append(merged_kem[['Algorithm', 'Family', 'Type', 'Compare Platform', 'Key Generation Ratio', 'Encapsulation Ratio', 'Decapsulation Ratio']])
                 except Exception as e:
                      print(f"Warning: Failed to merge/calculate KEM ratios for {plat_upper}: {e}")


             # Calculate Signature Ratios
             if not sig_ref.empty and not sig_plat.empty:
                 try:
                     merged_sig = pd.merge(
                         sig_ref[['Algorithm', 'Family', 'Type', 'Message Size (bytes)', 'Key Generation (ms)', 'Signing (ms)', 'Verification (ms)']],
                         sig_plat[['Algorithm', 'Message Size (bytes)', 'Key Generation (ms)', 'Signing (ms)', 'Verification (ms)']],
                         on=['Algorithm', 'Message Size (bytes)'], suffixes=('_ref', '_plat'), how='inner' # Ensure match
                     )
                     if not merged_sig.empty:
                          for op in ['Key Generation', 'Signing', 'Verification']:
                              time_ref = f'{op} (ms)_ref'; time_plat = f'{op} (ms)_plat'
                              mask = (merged_sig[time_ref] > 1e-9) & (merged_sig[time_plat].notna()) # Add notna check
                              merged_sig[f'{op} Ratio'] = np.nan
                              merged_sig.loc[mask, f'{op} Ratio'] = merged_sig.loc[mask, time_plat] / merged_sig.loc[mask, time_ref]
                          merged_sig['Compare Platform'] = plat_upper
                          ratio_dfs['sig'].append(merged_sig[['Algorithm', 'Family', 'Type', 'Message Size (bytes)', 'Compare Platform', 'Key Generation Ratio', 'Signing Ratio', 'Verification Ratio']])
                 except Exception as e:
                      print(f"Warning: Failed to merge/calculate Signature ratios for {plat_upper}: {e}")


        # Combine ratio DFs
        kem_ratios_all = pd.concat(ratio_dfs['kem'], ignore_index=True) if ratio_dfs['kem'] else pd.DataFrame()
        sig_ratios_all = pd.concat(ratio_dfs['sig'], ignore_index=True) if ratio_dfs['sig'] else pd.DataFrame()

        # --- Plotting Ratios ---
        ratio_metrics = {
             'kem': ['Key Generation Ratio', 'Encapsulation Ratio', 'Decapsulation Ratio'],
             'sig': ['Key Generation Ratio', 'Signing Ratio', 'Verification Ratio']
        }

        # Define consistent display family names for ratio plots
        family_mapping_ratio = {
             'ML-KEM': 'ML-KEM', 'FrodoKEM': 'FrodoKEM', 'NTRU-Prime': 'NTRU-Prime',
             'Code': 'Code-based', 'Hash': 'Hash-based', 'RSA': 'RSA', 'ECDH': 'ECDH',
             'ML-DSA': 'ML-DSA', 'Falcon': 'Falcon', 'Multivariate': 'Multivariate',
             'RSDP': 'RSDP', 'ECDSA': 'ECDSA', 'EdDSA': 'EdDSA'
         }


        for plat_comp in kem_ratios_all['Compare Platform'].unique():
            # KEM Ratio Plot
            kem_plat_ratios = kem_ratios_all[kem_ratios_all['Compare Platform'] == plat_comp].dropna(subset=ratio_metrics['kem'], how='all') # Drop rows where all ratios are NaN
            if not kem_plat_ratios.empty:
                 try:
                     plot_df = kem_plat_ratios.copy()
                     plot_df['Display Family'] = plot_df['Family'].map(lambda x: family_mapping_ratio.get(x, x))
                     plot_data = plot_df.melt(id_vars=['Algorithm', 'Display Family', 'Type'],
                                          value_vars=ratio_metrics['kem'],
                                          var_name='Operation', value_name='Performance Ratio').dropna(subset=['Performance Ratio'])

                     if not plot_data.empty:
                         plt.figure(figsize=(11, 7))
                         sns.boxplot(data=plot_data, x='Display Family', y='Performance Ratio', hue='Operation',
                                     palette='Set3', showfliers=False)
                         plt.yscale('log')
                         plt.axhline(1.0, color='grey', linestyle='--', alpha=0.7)
                         plt.title(f'KEM Performance Ratio ({plat_comp} / {ref_upper})')
                         plt.xlabel("Algorithm Family")
                         plt.ylabel(f'Ratio ({plat_comp} Time / {ref_upper} Time, log scale)')
                         plt.xticks(rotation=30, ha='right')
                         plt.legend(title='Operation', bbox_to_anchor=(1.05, 1), loc='upper left')
                         plt.tight_layout(rect=[0, 0, 0.85, 1])
                         plt.savefig(self.output_dir / 'figures' / f'appendix_kem_ratio_{plat_comp}_vs_{ref_upper}.pdf')
                         plt.close()
                     else: print(f"  Skipping KEM ratio plot for {plat_comp}: No valid ratio data after melt/dropna.")
                 except Exception as e:
                     print(f"Warning: Failed to generate KEM ratio plot for {plat_comp}: {e}")
                     plt.close()


            # Signature Ratio Plot
            sig_plat_ratios = sig_ratios_all[sig_ratios_all['Compare Platform'] == plat_comp].dropna(subset=ratio_metrics['sig'], how='all') # Drop rows where all ratios are NaN
            if not sig_plat_ratios.empty:
                 message_sizes = sorted(sig_plat_ratios['Message Size (bytes)'].unique())
                 if not message_sizes: continue
                 msg_size_example = message_sizes[len(message_sizes) // 2]
                 sig_ratios_example = sig_plat_ratios[sig_plat_ratios['Message Size (bytes)'] == msg_size_example]

                 if not sig_ratios_example.empty:
                     try:
                         plot_df = sig_ratios_example.copy()
                         plot_df['Display Family'] = plot_df['Family'].map(lambda x: family_mapping_ratio.get(x, x))
                         plot_data = plot_df.melt(id_vars=['Algorithm', 'Display Family', 'Type'],
                                              value_vars=ratio_metrics['sig'],
                                              var_name='Operation', value_name='Performance Ratio').dropna(subset=['Performance Ratio'])

                         if not plot_data.empty:
                             plt.figure(figsize=(11, 7))
                             sns.boxplot(data=plot_data, x='Display Family', y='Performance Ratio', hue='Operation',
                                         palette='Set3', showfliers=False)
                             plt.yscale('log')
                             plt.axhline(1.0, color='grey', linestyle='--', alpha=0.7)
                             plt.title(f'Signature Performance Ratio ({plat_comp} / {ref_upper}, {msg_size_example:,} Bytes)')
                             plt.xlabel("Algorithm Family")
                             plt.ylabel(f'Ratio ({plat_comp} Time / {ref_upper} Time, log scale)')
                             plt.xticks(rotation=30, ha='right')
                             plt.legend(title='Operation', bbox_to_anchor=(1.05, 1), loc='upper left')
                             plt.tight_layout(rect=[0, 0, 0.85, 1])
                             plt.savefig(self.output_dir / 'figures' / f'appendix_sig_ratio_{plat_comp}_vs_{ref_upper}_{msg_size_example}.pdf')
                             plt.close()
                         else: print(f"  Skipping Sig ratio plot for {plat_comp} (size {msg_size_example}): No valid ratio data after melt/dropna.")
                     except Exception as e:
                          print(f"Warning: Failed to generate Sig ratio plot for {plat_comp} (size {msg_size_example}): {e}")
                          plt.close()

        # --- Ratio Tables ---
        if not kem_ratios_all.empty:
             try:
                 kem_ratio_summary = kem_ratios_all.groupby(['Family', 'Type', 'Compare Platform'])[ratio_metrics['kem']].agg(['mean', 'median', 'min', 'max']).round(2)
                 kem_ratio_summary.columns = [' '.join(col).strip() for col in kem_ratio_summary.columns.values]
                 tex_path = self.output_dir / 'tables' / 'appendix_kem_platform_ratios.tex'
                 csv_path = self.output_dir / 'tables' / 'appendix_kem_platform_ratios.csv'
                 with open(tex_path, 'w') as f:
                     f.write(self._consolidated_df_to_latex(
                         kem_ratio_summary.reset_index(), # Reset index for table
                         caption=f'Summary of KEM Performance Ratios Relative to {ref_upper}',
                         label='tab:appendix_kem_ratios',
                         float_format='%.2f'
                     ))
                 kem_ratio_summary.reset_index().to_csv(csv_path, index=False, float_format='%.2f') # Save CSV
             except Exception as e:
                  print(f"Warning: Failed to generate KEM ratio summary table: {e}")

        if not sig_ratios_all.empty:
             try:
                 message_sizes = sorted(sig_ratios_all['Message Size (bytes)'].unique())
                 if message_sizes:
                      msg_size_example = message_sizes[len(message_sizes) // 2]
                      sig_ratios_example = sig_ratios_all[sig_ratios_all['Message Size (bytes)'] == msg_size_example]
                      if not sig_ratios_example.empty:
                          sig_ratio_summary = sig_ratios_example.groupby(['Family', 'Type', 'Compare Platform'])[ratio_metrics['sig']].agg(['mean', 'median', 'min', 'max']).round(2)
                          sig_ratio_summary.columns = [' '.join(col).strip() for col in sig_ratio_summary.columns.values]
                          tex_path = self.output_dir / 'tables' / f'appendix_sig_platform_ratios_{msg_size_example}.tex'
                          csv_path = self.output_dir / 'tables' / f'appendix_sig_platform_ratios_{msg_size_example}.csv'
                          with open(tex_path, 'w') as f:
                              f.write(self._consolidated_df_to_latex(
                                  sig_ratio_summary.reset_index(), # Reset index for table
                                  caption=f'Summary of Signature Performance Ratios Relative to {ref_upper} ({msg_size_example:,} Bytes)',
                                  label=f'tab:appendix_sig_ratios_{msg_size_example}',
                                  float_format='%.2f'
                              ))
                          sig_ratio_summary.reset_index().to_csv(csv_path, index=False, float_format='%.2f') # Save CSV
             except Exception as e:
                  print(f"Warning: Failed to generate Sig ratio summary table: {e}")

    # --- Main Execution ---
    def run_appendix_analysis(self):
        """Run the appendix analysis pipeline."""
        if self.platform_data['kem'].empty and self.platform_data['sig'].empty:
            print("No data available. Cannot run appendix analysis.")
            return

        self.generate_detailed_performance_tables()
        self.generate_platform_ratio_analysis()

        print(f"\nAppendix analysis complete. Results saved in {self.output_dir}")


def main():
    """Main execution function"""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description='Generate appendix analysis (detailed tables, ratios) for PQC benchmarks.'
    )
    parser.add_argument(
        '--results-dir',
        type=Path,
        default=Path('results'),
        help='Base directory containing platform benchmark result folders (default: results)'
    )
    parser.add_argument(
        '--no-tex',
        action='store_true',
        help='Disable LaTeX rendering for plots (requires matplotlib font handling)'
    )

    args = parser.parse_args()

    # Update mpl settings if --no-tex is used
    if args.no_tex:
        global USE_TEX
        USE_TEX = False
        mpl.rcParams.update({
            'text.usetex': False,
            'font.family': 'sans-serif',
            'pgf.texsystem': None,
            'pgf.rcfonts': None,
            'text.latex.preamble': '',
        })
        print("LaTeX rendering disabled.")

    try:
        analyzer = AppendixAnalyzer(args.results_dir)
        analyzer.run_appendix_analysis()

    except FileNotFoundError as e:
        print(f"Error: Input directory not found or missing files. {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
         print(f"Error: {e}", file=sys.stderr)
         sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during appendix analysis: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()