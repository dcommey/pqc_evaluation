#!/usr/bin/env python3
"""
Consolidated publication-quality analysis of post-quantum cryptography benchmarks.
Handles algorithm name duplication and generates figures and tables for the results section.
"""

import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import matplotlib as mpl
import warnings
import re
from adjustText import adjust_text

warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=UserWarning)
warnings.filterwarnings('ignore', category=pd.errors.PerformanceWarning)

USE_TEX = True

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
    'text.latex.preamble': r'\usepackage{amsmath} \usepackage{amsfonts} \usepackage{amssymb}' if USE_TEX else '',
    'pgf.texsystem': 'pdflatex' if USE_TEX else None,
    'pgf.rcfonts': False if USE_TEX else None,
})

class ConsolidatedAnalyzer:
    PLATFORMS = ['macos', 'ubuntu', 'raspberry']
    RESOURCE_PLATFORM = 'raspberry'
    REFERENCE_PLATFORM = 'macos'
    OUTPUT_SUBDIR = 'consolidated_analysis_v2'
    
    CONSOLIDATION_MAP = {
        'Kyber': 'ML-KEM',
        'CRYSTALS-Kyber': 'ML-KEM',
        'Dilithium': 'ML-DSA',
        'CRYSTALS-Dilithium': 'ML-DSA',
    }
    
    REVERSE_CONSOLIDATION_MAP = {v: k for k, v in CONSOLIDATION_MAP.items()}

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

    FAMILY_DISPLAY_MAP = {
        'ML-KEM': 'ML-KEM',
        'ML-DSA': 'ML-DSA',
        'EdDSA': 'EdDSA',
        'ECDSA': 'ECDSA',
        'ECDH': 'ECDH',
        'RSA': 'RSA',
        'Falcon': 'Falcon',
        'NTRU-Prime': 'NTRU-Prime',
        'Code': 'Code-based',
        'Hash': 'Hash-based',
        'Multivariate': 'Multivariate',
        'RSDP': 'RSDP',
        'FrodoKEM': 'FrodoKEM'
    }

    def __init__(self, results_base: Path):
        self.results_base = results_base
        self.output_dir = results_base / self.OUTPUT_SUBDIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / 'figures').mkdir(exist_ok=True)
        (self.output_dir / 'tables').mkdir(exist_ok=True)
        (self.output_dir / 'data').mkdir(exist_ok=True)

        global USE_TEX
        if not USE_TEX:
            print("LaTeX rendering disabled for plots.")
            mpl.rcParams.update({
                'font.family': 'sans-serif',
                'text.usetex': False,
                'text.latex.preamble': '',
                'pgf.texsystem': None,
                'pgf.rcfonts': None,
            })

        print("Loading raw results...")
        self.raw_results = self._load_all_results()

        self.resource_platform_available = self.RESOURCE_PLATFORM in self.raw_results
        if not self.resource_platform_available:
            print(f"Warning: Resource platform '{self.RESOURCE_PLATFORM}' data not found. Resource plots will be skipped.")

        self.reference_platform_available = self.REFERENCE_PLATFORM in self.raw_results
        if not self.reference_platform_available:
             print(f"Warning: Reference platform '{self.REFERENCE_PLATFORM}' data not found. Some plots/tables might be skipped.")

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
        # Handle names like 'ML-KEM-512', 'Kyber512', 'Falcon-512', 'RSA-2048', 'SPHINCS+-SHA2-128f-simple'
        patterns = [
             # Match NIST names first (e.g., ML-KEM-512, ML-DSA-44)
             r"^(ML-KEM|ML-DSA)-(\d+)",
             # Match specific non-NIST names that map directly (e.g., Kyber512, Dilithium2)
             r"^(Kyber|Dilithium)(\d+)",
             # Match Falcon variants
             r"^(Falcon(?:-padded)?)-(\d+)",
             # Other PQC schemes
             r"([a-zA-Z\+\-]+[a-zA-Z]+)-([\w\-]+)", # General form like SPHINCS+-SHA2-128f-simple or Classic-McEliece-348864
             # Classical schemes
             r"^(RSA|ECDSA|EdDSA|Ed25519)-?(\d+)?",
             # Fallback for names without clear separators/params
             r"^([a-zA-Z\+]+)",
        ]
        for pattern in patterns:
             match = re.match(pattern, name)
             if match:
                 base = match.group(1)
                 params = match.group(2) if len(match.groups()) > 1 and match.group(2) else ''

                 # Apply specific cleanups first (don't affect Kyber/Dilithium base)
                 if base == 'sntrup': base = 'NTRU-Prime'
                 if base == 'Classic-McEliece' and params: params = params.replace('f', '')
                 if base == 'Ed25519': 
                      base = 'EdDSA' 
                      params = '256' if not params else params

                 # --- Conditionally Apply Base Standardization --- 
                 if apply_base_std:
                     # 1. Kyber -> ML-KEM
                     if base == 'Kyber': base = 'ML-KEM'
                     # 2. Dilithium -> ML-DSA
                     if base == 'Dilithium': base = 'ML-DSA'
                     # 3. Handle CRYSTALS prefix 
                     if base.startswith('CRYSTALS-'):
                         if 'Kyber' in base: base = 'ML-KEM'
                         elif 'Dilithium' in base: base = 'ML-DSA'

                 return base, params
                 
        # Fallback if no pattern matched
        print(f"Warning: Could not parse algorithm name: {name}")
        return name, ''

    def _prepare_and_consolidate_data(self) -> dict:
        """Prepare DataFrames for analysis, consolidating duplicate algorithms."""
        all_platform_data = {'kem': [], 'sig': []}
        print("  Loading initial data...")
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
            
            # --- Step 1: Parse initial name - Keep the *very* original base for mapping --- 
            # We need two parses: one to get the raw base/params for mapping, 
            # and one that applies base standardization (like Kyber->ML-KEM) for later use.
            raw_parts = df['Algorithm'].apply(lambda x: pd.Series(self._get_algorithm_parts(x, apply_base_std=False), 
                                                                  index=['Raw Base Name', 'Raw Params']))
            std_base_parts = df['Algorithm'].apply(lambda x: pd.Series(self._get_algorithm_parts(x, apply_base_std=True), 
                                                                        index=['Initial Std Base Name', 'Initial Params']))

            df['Raw Base Name'] = raw_parts['Raw Base Name']
            df['Raw Params'] = raw_parts['Raw Params']
            df['Initial Std Base Name'] = std_base_parts['Initial Std Base Name']
            df['Initial Params'] = std_base_parts['Initial Params'] # Params should be same from both parses

            # --- Step 2: Determine Final Standard Base, Final Standard Params, and Original Status --- 
            standard_tuples = []
            debug_algorithms = ['Kyber512', 'ML-KEM-512', 'Dilithium2', 'ML-DSA-44', 'Dilithium5', 'ML-DSA-87'] 
            for index, row in df.iterrows():
                # Use RAW base/params for the parameter map lookup
                raw_base = row['Raw Base Name']
                raw_params = row['Raw Params']
                raw_tuple = (raw_base, raw_params)
                original_algo_name = row['Original Algorithm']
                # Get the base name that might have already been standardized (e.g., ML-KEM)
                initial_std_base = row['Initial Std Base Name'] 

                # Check the specific parameter map using the RAW tuple
                mapped_std_tuple = self.PARAMETER_MAP.get(raw_tuple)

                final_std_base = initial_std_base # Default to the already standardized base name
                final_std_params = row['Initial Params'] # Default to initial params
                is_original_standard = True # Assume standard unless mapped or base changed

                if mapped_std_tuple: 
                    # Found in map: Use mapped values, flag as originally non-standard
                    final_std_base, final_std_params = mapped_std_tuple
                    is_original_standard = False
                    # DEBUG PRINT 
                    if original_algo_name in debug_algorithms:
                        print(f"[DEBUG] Mapped: '{original_algo_name}' (Raw: {raw_tuple}) -> Final: ({final_std_base}, {final_std_params}) [OrigStd=False]")
                else:
                    # Not in specific map. Check if the base name was changed by initial standardization (e.g. Kyber->ML-KEM)
                    if initial_std_base != raw_base:
                        is_original_standard = False # Base name was changed, so not original standard form
                    # Keep final_std_base as initial_std_base and final_std_params as initial_params
                    # DEBUG PRINT 
                    if original_algo_name in debug_algorithms:
                         print(f"[DEBUG] Not Mapped: '{original_algo_name}' (Raw: {raw_tuple}) -> Final: ({final_std_base}, {final_std_params}) [OrigStd={is_original_standard}]")
                
                standard_tuples.append((final_std_base, final_std_params, is_original_standard))
            
            # Assign the calculated standard info back to the DataFrame
            standard_info_df = pd.DataFrame(standard_tuples, index=df.index, columns=['Std Base Name', 'Std Params', 'Is Original Name Standard'])
            df['Std Base Name'] = standard_info_df['Std Base Name']
            df['Std Params'] = standard_info_df['Std Params']
            df['Is Original Name Standard'] = standard_info_df['Is Original Name Standard']
            
            # --- Verification Step (Optional Debugging) ---
            # print("\n--- Post-Standardization Check ---")
            # print(df[['Original Algorithm', 'Raw Base Name', 'Raw Params', 'Initial Std Base Name', 'Initial Params', 'Std Base Name', 'Std Params', 'Is Original Name Standard']].head(20))
            # print("----------------------------------\n")

        print("  Consolidating algorithm entries based on standardized names/params...")
        # Pass the standardized names/params columns to consolidation
        consolidated_kem_df = self._consolidate_df(kem_df, base_col='Std Base Name', params_col='Std Params', standard_flag_col='Is Original Name Standard')
        consolidated_sig_df = self._consolidate_df(sig_df, base_col='Std Base Name', params_col='Std Params', standard_flag_col='Is Original Name Standard')

        # --- DEBUG: Check final names before dropping intermediate cols ---
        print("\n[DEBUG] Checking final reconstructed names after consolidation:")
        for df_name, df in zip(['KEM', 'SIG'], [consolidated_kem_df, consolidated_sig_df]):
            if df.empty: continue
            print(f"--- {df_name} DataFrame --- ")
            # Temporarily reconstruct name for debug print
            temp_algo_names = df.apply(lambda row: f"{row['Std Base Name']}-{row['Std Params']}" if row['Std Params'] else row['Std Base Name'], axis=1)
            relevant_algos = temp_algo_names[temp_algo_names.str.contains('ML-KEM|ML-DSA', regex=True)]
            if not relevant_algos.empty:
                 print(relevant_algos.unique())
            else:
                 print("No ML-KEM or ML-DSA found after consolidation.")
        # --- END DEBUG ---

        print("  Finalizing algorithm names and families...")
        for df in [consolidated_kem_df, consolidated_sig_df]:
            if df.empty: continue
            # --- Step 3: Reconstruct final Algorithm name from STANDARD parts --- 
            df['Algorithm'] = df.apply(lambda row: f"{row['Std Base Name']}-{row['Std Params']}" if row['Std Params'] else row['Std Base Name'], axis=1)
            
            df['Family'] = df['Std Base Name']
            # Apply family standardization rules
            df.loc[df['Family'].isin(['Ed', 'Ed25519']), 'Family'] = 'EdDSA'
            df.loc[df['Family'].isin(['BIKE', 'HQC', 'Classic-McEliece']), 'Family'] = 'Code'
            # Correctly identify all SPHINCS+ variants
            df.loc[df['Family'].str.startswith('SPHINCS+', na=False), 'Family'] = 'Hash'
            df.loc[df['Family'].isin(['MAYO', 'Rainbow']), 'Family'] = 'Multivariate'
            df.loc[df['Family'].str.contains('cross', case=False, na=False), 'Family'] = 'RSDP'

            # --- Step 4: Drop intermediate columns --- 
            cols_to_drop = ['Original Algorithm', 'Raw Base Name', 'Raw Params',
                            'Initial Std Base Name', 'Initial Params', 
                            'Std Base Name', 'Std Params', 'Is Original Name Standard']
            df.drop(columns=[col for col in cols_to_drop if col in df.columns], inplace=True)

        print("  Saving processed data...")
        if not consolidated_kem_df.empty:
             consolidated_kem_df.to_csv(self.output_dir / 'data' / 'consolidated_kem_data.csv', index=False)
        if not consolidated_sig_df.empty:
             consolidated_sig_df.to_csv(self.output_dir / 'data' / 'consolidated_sig_data.csv', index=False)

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
        required_cols = ['Platform', base_col, params_col, standard_flag_col, 'Algorithm']
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

            if not standard_entries.empty and not non_standard_entries.empty:
                # --- DEBUG PRINT --- 
                group_base = group_key[1] if len(group_key) > 1 else group_key[0] # Adjust index based on group_cols
                if group_base in ['ML-KEM', 'ML-DSA']:
                     print(f"[DEBUG] Consolidating Group {group_key}: Found {len(standard_entries)} standard / {len(non_standard_entries)} non-standard entries.")
                     print(f"  Standard Originals: {standard_entries['Original Algorithm'].tolist()}")
                     print(f"  Non-Standard Originals: {non_standard_entries['Original Algorithm'].tolist()}")
                     print(f"  Dropping indices: {non_standard_entries.index.tolist()}")
                # --- END DEBUG --- 
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
        name_lower = name.lower(); match = re.search(r'(\d+)$', name)
        if not match: return 1 if 'ed25519' in name_lower else 0
        key_size = int(match.group(1))
        if 'rsa' in name_lower or 'ecdh' in name_lower or 'ecdsa' in name_lower:
            if key_size >= 512: return 5;
            if key_size >= 384: return 3;
            if key_size >= 256: return 1;
        return 0

    # --- Enhanced LaTeX Table Formatting ---
    def _consolidated_df_to_latex(self, df: pd.DataFrame, caption: str, label: str, **kwargs) -> str:
        """Formats a DataFrame to LaTeX with booktabs style."""
        latex_kwargs = { 'index': False, 'escape': False, 'longtable': True, 'caption': caption,
                         'label': label, 'column_format': None, 'float_format': '%.2f', 'na_rep': '-' }
        latex_kwargs.update(kwargs)
        if latex_kwargs['column_format'] is None:
            num_cols = len(df.columns); latex_kwargs['column_format'] = 'l' + 'r' * (num_cols -1) if num_cols > 0 else 'l'
        
        # Use a context manager to potentially suppress floating environment in longtable
        # This often helps with complex layouts but might need adjustment
        # from pandas.io.formats.latex import Styler
        # df_styler = df.style # Not directly using styler here, keeping original to_latex

        try:
            latex_str = df.to_latex(**latex_kwargs)
        except Exception as e:
            print(f"Error during initial to_latex call for {label}: {e}")
            return f"% Error generating LaTeX for table {label}"

        lines = latex_str.splitlines()
        
        # More robust rule insertion
        try:
            begin_lt_index = -1
            header_line_index = -1
            midrule_inserted = False
            
            for i, line in enumerate(lines):
                if '\\begin{longtable}' in line:
                    begin_lt_index = i
                if begin_lt_index != -1 and header_line_index == -1 and not line.strip().startswith('\\') and line.strip():
                    # Heuristic: First non-command line after \begin{longtable} is likely header
                     header_line_index = i
                     # Find the line *before* the header content to insert toprule
                     toprule_pos = i 
                     # Go back to find the line with column format definition
                     for j in range(i - 1, begin_lt_index, -1):
                         if '{' in lines[j] and '}' in lines[j]: # Likely column format line
                              toprule_pos = j + 1
                              break
                     lines.insert(toprule_pos, '\\toprule')
                     # Adjust index due to insertion
                     header_line_index += 1

                if header_line_index != -1 and not midrule_inserted and line.strip() == '\\midrule':
                     # If pandas already added a midrule, we don't need another complex search
                     midrule_inserted = True

                if header_line_index != -1 and not midrule_inserted and ('\\endfirsthead' in line or '\\endhead' in line):
                    # Insert midrule after header definition ends in longtable
                    lines.insert(i + 1, '\\midrule')
                    midrule_inserted = True
                    
            # If standard midrule wasn't found, try inserting after the found header_line_index
            if header_line_index != -1 and not midrule_inserted:
                 lines.insert(header_line_index + 1, '\\midrule')

            # Add bottomrule before end{longtable}
            end_lt_index = -1
            for i in range(len(lines) - 1, -1, -1):
                if '\\end{longtable}' in lines[i]:
                    end_lt_index = i
                    break
            if end_lt_index != -1:
                lines.insert(end_lt_index, '\\bottomrule')
            else:
                 print(f"Warning: Could not find end{{longtable}} for table '{label}'.")
                 
        except Exception as e:
             print(f"Error adding booktabs rules for {label}: {e}")
             # Return the original unformatted string if rules fail
             return latex_str

        return '\n'.join(lines)


    # --- Analysis and Plotting Functions (Operating on CONSOLIDATED data) ---

    def generate_platform_comparison(self):
        """Generate cross-platform comparison plots and tables using consolidated data."""
        print("  Generating platform comparison figures and tables...")
        self._generate_kem_platform_comparison()
        self._generate_sig_platform_comparison()

    def _generate_kem_platform_comparison(self):
        """Generate KEM cross-platform comparison using consolidated data."""
        kem_data = self.platform_data['kem']
        if kem_data.empty:
            print("  Skipping KEM platform comparison: No data.")
            return

        plt.figure(figsize=(10, 6))
        metrics = ['Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)']
        plot_data = kem_data.melt(
            id_vars=['Platform', 'Algorithm', 'Type'],
            value_vars=metrics,
            var_name='Operation',
            value_name='Time (ms)'
        )
        if plot_data.empty: return # Skip if no data to plot

        sns.boxplot(
            data=plot_data, x='Platform', y='Time (ms)', hue='Operation',
            palette='viridis', showfliers=False, order=sorted(kem_data['Platform'].unique())
        )
        plt.yscale('log')
        plt.title('KEM Performance Across Platforms')
        plt.xlabel("Platform")
        plt.ylabel('Time (ms, log scale)')
        plt.legend(title='Operation', bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout(rect=[0, 0, 0.85, 1])
        plt.savefig(self.output_dir / 'figures' / 'kem_platform_perf.pdf')
        plt.close()

        stats_table = []
        for platform in sorted(kem_data['Platform'].unique()):
            platform_df = kem_data[kem_data['Platform'] == platform]
            if platform_df.empty: continue
            try:
                platform_stats = platform_df.groupby('Type')[metrics].agg(['mean', 'std']).round(2)
                if platform_stats.empty: continue
                valid_cols = [col for col in platform_stats.columns if col[0] in metrics]
                platform_stats = platform_stats[valid_cols]
                platform_stats.columns = [f"{col[0].split(' ')[0]} {col[1].upper()}" for col in platform_stats.columns]
                platform_stats['Platform'] = platform
                stats_table.append(platform_stats.reset_index())
            except Exception as e:
                 print(f"Warning: Could not compute stats for KEMs on {platform}: {e}")

        if stats_table:
            stats_df = pd.concat(stats_table)
            stats_df = stats_df[['Platform', 'Type'] + [col for col in stats_df.columns if col not in ['Platform', 'Type']]]
            tex_path = self.output_dir / 'tables' / 'kem_platform_stats.tex'
            csv_path = self.output_dir / 'tables' / 'kem_platform_stats.csv'
            with open(tex_path, 'w') as f:
                f.write(self._consolidated_df_to_latex(
                    stats_df,
                    caption='KEM Performance Statistics Across Platforms (ms)',
                    label='tab:kem_platform_stats',
                    float_format='%.2f'
                ))
            stats_df.to_csv(csv_path, index=False, float_format='%.2f') # Save CSV

    def _generate_sig_platform_comparison(self):
        """Generate signature cross-platform comparison using consolidated data."""
        sig_data = self.platform_data['sig']
        if sig_data.empty:
             print("  Skipping Signature platform comparison: No data.")
             return

        metrics = ['Key Generation (ms)', 'Signing (ms)', 'Verification (ms)']
        message_sizes = sorted(sig_data['Message Size (bytes)'].unique())
        if not message_sizes: return # Exit if no message sizes found
        msg_size_example = message_sizes[len(message_sizes) // 2] # Use median size

        plt.figure(figsize=(12, 7))
        plot_data = sig_data[sig_data['Message Size (bytes)'] == msg_size_example].melt(
            id_vars=['Platform', 'Algorithm', 'Type', 'Family'],
            value_vars=metrics,
            var_name='Operation',
            value_name='Time (ms)'
        )
        if plot_data.empty: return # Skip if no data for example size

        sns.boxplot(
            data=plot_data, x='Platform', y='Time (ms)', hue='Operation',
            palette='viridis', showfliers=False, order=sorted(sig_data['Platform'].unique())
        )
        plt.yscale('log')
        plt.title(f'Signature Performance Across Platforms ({msg_size_example:,} Bytes)')
        plt.xlabel("Platform")
        plt.ylabel('Time (ms, log scale)')
        plt.legend(title='Operation', bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout(rect=[0, 0, 0.85, 1])
        plt.savefig(self.output_dir / 'figures' / f'sig_platform_perf_{msg_size_example}.pdf')
        plt.close()

        for msg_size in message_sizes:
            stats_table = []
            msg_data_for_table = sig_data[sig_data['Message Size (bytes)'] == msg_size]
            if msg_data_for_table.empty: continue

            for platform in sorted(msg_data_for_table['Platform'].unique()):
                platform_data = msg_data_for_table[msg_data_for_table['Platform'] == platform]
                if platform_data.empty: continue
                try:
                    platform_stats = platform_data.groupby('Type')[metrics].agg(['mean', 'std']).round(2)
                    if platform_stats.empty: continue
                    valid_cols = [col for col in platform_stats.columns if col[0] in metrics]
                    platform_stats = platform_stats[valid_cols]
                    platform_stats.columns = [f"{col[0].split(' ')[0]} {col[1].upper()}" for col in platform_stats.columns]
                    platform_stats['Platform'] = platform
                    stats_table.append(platform_stats.reset_index())
                except Exception as e:
                     print(f"Warning: Could not compute stats for Sigs (size {msg_size}) on {platform}: {e}")

            if stats_table:
                stats_df = pd.concat(stats_table)
                stats_df = stats_df[['Platform', 'Type'] + [col for col in stats_df.columns if col not in ['Platform', 'Type']]]
                tex_path = self.output_dir / 'tables' / f'sig_platform_stats_{msg_size}.tex'
                csv_path = self.output_dir / 'tables' / f'sig_platform_stats_{msg_size}.csv'
                with open(tex_path, 'w') as f:
                    f.write(self._consolidated_df_to_latex(
                        stats_df,
                        caption=f'Signature Performance Statistics (ms, {msg_size:,} Bytes)',
                        label=f'tab:sig_platform_stats_{msg_size}',
                        float_format='%.2f'
                    ))
                stats_df.to_csv(csv_path, index=False, float_format='%.2f') # Save CSV

    def generate_communication_analysis(self):
        """Generate communication overhead analysis using consolidated data."""
        print("  Generating communication overhead figures and tables...")
        kem_data = self.platform_data['kem']
        sig_data = self.platform_data['sig']

        if not self.reference_platform_available:
             print("  Skipping communication analysis: Reference platform data unavailable.")
             return

        ref_platform_upper = self.REFERENCE_PLATFORM.upper()
        kem_data_ref = kem_data[kem_data['Platform'] == ref_platform_upper].drop_duplicates(subset=['Algorithm'])
        sig_data_ref = sig_data[sig_data['Platform'] == ref_platform_upper]

        if not kem_data_ref.empty:
            # Add display family for consistent labels
            kem_data_ref['Display Family'] = kem_data_ref['Family'].map(lambda x: self.FAMILY_DISPLAY_MAP.get(x, x))
            
            plt.figure(figsize=(10, 7))
            ax = sns.scatterplot( # Get the axes object
                data=kem_data_ref, x='Public Key Size (bytes)', y='Ciphertext Size (bytes)',
                hue='Display Family', style='Security Level', size='Security Level',
                sizes=(40, 200), alpha=0.8, palette='tab10', legend='full'
            )
            plt.xscale('log')
            plt.yscale('log')
            plt.title('KEM Communication Overhead')
            plt.xlabel('Public Key Size (bytes, log scale)')
            plt.ylabel('Ciphertext Size (bytes, log scale)')
            plt.grid(True, which="both", ls="--", alpha=0.3)

            # --- adjustText integration for KEM ---
            texts = []
            for idx, point in kem_data_ref.iterrows():
                label_text = point['Algorithm']
                # More strict label criteria & specific handling for clustered families
                should_label = False
                if point['Family'] == 'Code': # Only label highest security Classic McEliece
                    if point['Algorithm'] == 'Classic-McEliece-6960119': should_label = True
                elif point['Family'] == 'FrodoKEM': # Only label highest security Frodo
                    if point['Algorithm'] == 'FrodoKEM-1344-SHAKE': should_label = True 
                elif (point['Security Level'] >= 5 or # Highest NIST level
                      point['Public Key Size (bytes)'] > 300000 or # Even larger sizes
                      point['Ciphertext Size (bytes)'] > 30000):
                     should_label = True
                
                if should_label:
                    texts.append(plt.text(point['Public Key Size (bytes)'],
                                          point['Ciphertext Size (bytes)'],
                                          label_text, fontsize=5)) # Reduced fontsize
            if texts:
                adjust_text(texts, ax=ax, 
                            arrowprops=dict(arrowstyle='-', color='gray', lw=0.5, alpha=0.6),
                            expand_points=(1.8, 1.8), # Increased expansion
                            force_text=(0.8, 0.8), # Increased force
                            force_points=(0.6, 0.6))
            # --- End adjustText integration ---

            plt.legend(title='Family / Sec Level', bbox_to_anchor=(1.05, 1), loc='upper left')
            plt.tight_layout(rect=[0, 0, 0.82, 1])
            plt.savefig(self.output_dir / 'figures' / 'kem_comm_overhead.pdf')
            plt.close()

            # KEM Communication Cost Table (unchanged)
            size_metrics = ['Public Key Size (bytes)', 'Ciphertext Size (bytes)', 'Shared Secret Size (bytes)']
            try:
                 # Use Display Family for consistent table headers
                 kem_data_table = kem_data_ref.copy()
                 kem_data_table['Family'] = kem_data_table['Display Family']
                 comm_stats = kem_data_table.groupby(['Family', 'Type'])[size_metrics].agg(['mean', 'min', 'max']).round(0).astype(int)
                 valid_cols = [col for col in comm_stats.columns if col[0] in size_metrics]
                 comm_stats = comm_stats[valid_cols]
                 comm_stats.columns = [f"{col[0].replace(' (bytes)','')} {col[1].upper()}" for col in comm_stats.columns]
                 tex_path = self.output_dir / 'tables' / 'kem_comm_costs.tex'
                 csv_path = self.output_dir / 'tables' / 'kem_comm_costs.csv'
                 with open(tex_path, 'w') as f:
                     f.write(self._consolidated_df_to_latex(
                        comm_stats,
                        caption='KEM Communication Costs by Family (bytes)',
                        label='tab:kem_comm_costs',
                        float_format='%d'
                    ))
                 comm_stats.reset_index().to_csv(csv_path, index=False, float_format='%d') # Save CSV
            except Exception as e:
                 print(f"Warning: Could not generate KEM comm costs table: {e}")


        if not sig_data_ref.empty:
            try:
                sig_size_avg = sig_data_ref.groupby(
                    ['Algorithm', 'Type', 'Security Level', 'Family', 'Public Key Size (bytes)']
                )['Signature Size (bytes)'].mean().reset_index()
                
                # Add display family
                sig_size_avg['Display Family'] = sig_size_avg['Family'].map(lambda x: self.FAMILY_DISPLAY_MAP.get(x, x))
            except Exception as e:
                print(f"Warning: Could not calculate average signature size: {e}")
                sig_size_avg = pd.DataFrame() # Assign empty DF

            if not sig_size_avg.empty:
                plt.figure(figsize=(10, 7))
                ax = sns.scatterplot( # Get the axes object
                    data=sig_size_avg, x='Public Key Size (bytes)', y='Signature Size (bytes)',
                    hue='Display Family', style='Security Level', size='Security Level',
                    sizes=(40, 200), alpha=0.8, palette='tab10', legend='full'
                )
                plt.xscale('log')
                plt.yscale('log')
                plt.title('Signature Communication Overhead')
                plt.xlabel('Public Key Size (bytes, log scale)')
                plt.ylabel('Avg. Signature Size (bytes, log scale)')
                plt.grid(True, which="both", ls="--", alpha=0.3)

                # --- adjustText integration for Signatures ---
                texts = []
                for idx, point in sig_size_avg.iterrows():
                    label_text = point['Algorithm']
                    # More strict label criteria
                    if (point['Security Level'] >= 5 or # Only highest level
                        point['Signature Size (bytes)'] > 50000 or # Even larger sigs
                        point['Public Key Size (bytes)'] > 10000): # Even larger keys
                         texts.append(plt.text(point['Public Key Size (bytes)'],
                                               point['Signature Size (bytes)'],
                                               label_text, fontsize=5)) # Reduced fontsize
                if texts:
                    adjust_text(texts, ax=ax, 
                                arrowprops=dict(arrowstyle='-', color='gray', lw=0.5, alpha=0.6),
                                expand_points=(1.8, 1.8),
                                force_text=(0.8, 0.8), 
                                force_points=(0.6, 0.6))
                # --- End adjustText integration ---

                plt.legend(title='Family / Sec Level', bbox_to_anchor=(1.05, 1), loc='upper left')
                plt.tight_layout(rect=[0, 0, 0.82, 1])
                plt.savefig(self.output_dir / 'figures' / 'sig_comm_overhead.pdf')
                plt.close()

                # Signature Communication Cost Table (unchanged)
                sig_size_metrics = ['Public Key Size (bytes)', 'Signature Size (bytes)']
                try:
                     # Use Display Family for consistent table headers
                     sig_size_table = sig_size_avg.copy()
                     sig_size_table['Family'] = sig_size_table['Display Family']
                     sig_comm_stats = sig_size_table.groupby(['Family', 'Type'])[sig_size_metrics].agg(['mean', 'min', 'max']).round(0).astype(int)
                     valid_cols = [col for col in sig_comm_stats.columns if col[0] in sig_size_metrics]
                     sig_comm_stats = sig_comm_stats[valid_cols]
                     sig_comm_stats.columns = [f"{col[0].replace(' (bytes)','')} {col[1].upper()}" for col in sig_comm_stats.columns]
                     tex_path = self.output_dir / 'tables' / 'sig_comm_costs.tex'
                     csv_path = self.output_dir / 'tables' / 'sig_comm_costs.csv'
                     with open(tex_path, 'w') as f:
                         f.write(self._consolidated_df_to_latex(
                            sig_comm_stats,
                            caption='Signature Communication Costs by Family (bytes)',
                            label='tab:sig_comm_costs',
                            float_format='%d'
                        ))
                     sig_comm_stats.reset_index().to_csv(csv_path, index=False, float_format='%d') # Save CSV
                except Exception as e:
                     print(f"Warning: Could not generate Sig comm costs table: {e}")


    def generate_security_analysis(self):
        """Generate security level analysis using consolidated data."""
        print("  Generating security level figures and tables...")
        if not self.reference_platform_available:
             print("  Skipping security analysis: Reference platform data unavailable.")
             return

        ref_platform_upper = self.REFERENCE_PLATFORM.upper()
        kem_data = self.platform_data['kem'][self.platform_data['kem']['Platform'] == ref_platform_upper]
        sig_data = self.platform_data['sig'][self.platform_data['sig']['Platform'] == ref_platform_upper]

        if not kem_data.empty:
            kem_perf_metrics = ['Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)']
            plot_data_kem = kem_data.melt(
                id_vars=['Security Level', 'Type', 'Algorithm', 'Family'],
                value_vars=kem_perf_metrics, var_name='Operation', value_name='Time (ms)'
            )
            if not plot_data_kem.empty:
                plt.figure(figsize=(10, 6))
                sns.boxplot(data=plot_data_kem, x='Security Level', y='Time (ms)', hue='Operation', palette='magma', showfliers=False)
                plt.yscale('log')
                plt.title(f'KEM Performance vs NIST Security Level ({ref_platform_upper})')
                plt.xlabel('NIST Security Level')
                plt.ylabel('Time (ms, log scale)')
                plt.legend(title='Operation', bbox_to_anchor=(1.05, 1), loc='upper left')
                plt.tight_layout(rect=[0, 0, 0.85, 1])
                plt.savefig(self.output_dir / 'figures' / 'kem_security_analysis.pdf')
                plt.close()

        if not sig_data.empty:
            message_sizes = sorted(sig_data['Message Size (bytes)'].unique())
            if message_sizes:
                 msg_size_example = message_sizes[len(message_sizes) // 2]
                 sig_data_example = sig_data[sig_data['Message Size (bytes)'] == msg_size_example]

                 if not sig_data_example.empty:
                     sig_perf_metrics = ['Key Generation (ms)', 'Signing (ms)', 'Verification (ms)']
                     plot_data_sig = sig_data_example.melt(
                         id_vars=['Security Level', 'Type', 'Algorithm', 'Family'],
                         value_vars=sig_perf_metrics, var_name='Operation', value_name='Time (ms)'
                     )
                     if not plot_data_sig.empty:
                         plt.figure(figsize=(10, 6))
                         sns.boxplot(data=plot_data_sig, x='Security Level', y='Time (ms)', hue='Operation', palette='magma', showfliers=False)
                         plt.yscale('log')
                         plt.title(f'Signature Performance vs NIST Security Level ({msg_size_example:,} Bytes, {ref_platform_upper})')
                         plt.xlabel('NIST Security Level')
                         plt.ylabel('Time (ms, log scale)')
                         plt.legend(title='Operation', bbox_to_anchor=(1.05, 1), loc='upper left')
                         plt.tight_layout(rect=[0, 0, 0.85, 1])
                         plt.savefig(self.output_dir / 'figures' / f'sig_security_analysis_{msg_size_example}.pdf')
                         plt.close()

        security_impact_list = []
        try:
            if not kem_data.empty:
                kem_impact = kem_data.groupby(['Security Level', 'Type'])[['Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)', 'Public Key Size (bytes)', 'Ciphertext Size (bytes)']].mean()
                kem_impact.columns = pd.MultiIndex.from_product([['KEM'], kem_impact.columns])
                security_impact_list.append(kem_impact)
        except Exception as e:
            print(f"Warning: Could not compute KEM security impact stats: {e}")

        try:
            if not sig_data.empty:
                sig_avg_perf = sig_data.groupby(['Security Level', 'Type', 'Algorithm'])[['Signing (ms)', 'Verification (ms)']].mean()
                sig_avg_sizes = sig_data.groupby(['Security Level', 'Type', 'Algorithm'])[['Public Key Size (bytes)', 'Signature Size (bytes)']].first() # Use first to avoid averaging sizes incorrectly
                sig_impact_data = pd.concat([sig_avg_perf, sig_avg_sizes], axis=1).reset_index()
                sig_impact = sig_impact_data.groupby(['Security Level', 'Type'])[['Signing (ms)', 'Verification (ms)', 'Public Key Size (bytes)', 'Signature Size (bytes)']].mean()
                sig_impact.columns = pd.MultiIndex.from_product([['Signature'], sig_impact.columns])
                security_impact_list.append(sig_impact)
        except Exception as e:
             print(f"Warning: Could not compute Signature security impact stats: {e}")


        if security_impact_list:
            try:
                impact_df_multi = pd.concat(security_impact_list, axis=1)
                impact_df_pivot = impact_df_multi.unstack(level='Type')
                impact_df_pivot = impact_df_pivot.reorder_levels([1, 2, 0], axis=1).sort_index(axis=1)
                impact_df_pivot.columns = [' '.join(filter(None, col)).strip() for col in impact_df_pivot.columns.values]

                tex_path = self.output_dir / 'tables' / 'security_impact.tex'
                csv_path = self.output_dir / 'tables' / 'security_impact.csv'
                with open(tex_path, 'w') as f:
                     f.write(self._consolidated_df_to_latex(
                         impact_df_pivot.round(2),
                         caption=f'Impact of Security Level on Avg Performance and Size ({ref_platform_upper})',
                         label='tab:security_impact',
                         float_format='%.2f', na_rep='-'
                     ))
                impact_df_pivot.round(2).reset_index().to_csv(csv_path, index=False, float_format='%.2f', na_rep='-') # Save CSV
            except Exception as e:
                 print(f"Warning: Failed to generate security impact table: {e}")

    def generate_family_analysis(self):
        """Generate algorithm family analysis using consolidated data."""
        print("  Generating algorithm family figures and tables...")
        if not self.reference_platform_available:
             print("  Skipping family analysis: Reference platform data unavailable.")
             return

        ref_platform_upper = self.REFERENCE_PLATFORM.upper()
        kem_data = self.platform_data['kem'][self.platform_data['kem']['Platform'] == ref_platform_upper]
        sig_data = self.platform_data['sig'][self.platform_data['sig']['Platform'] == ref_platform_upper]

        if not kem_data.empty:
            metrics = ['Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)']
            size_metrics = ['Public Key Size (bytes)', 'Ciphertext Size (bytes)']

            # Add display family for consistent labels
            kem_data['Display Family'] = kem_data['Family'].map(lambda x: self.FAMILY_DISPLAY_MAP.get(x, x))

            fig, axes = plt.subplots(2, 1, figsize=(11, 8), sharex=True)
            fig.suptitle(f'KEM Family Comparison ({ref_platform_upper})')

            perf_data = kem_data.melt(id_vars=['Display Family', 'Algorithm'], value_vars=metrics, var_name='Operation', value_name='Time (ms)')
            if not perf_data.empty:
                sns.boxplot(data=perf_data, x='Display Family', y='Time (ms)', hue='Operation', palette='Set2', ax=axes[0], showfliers=False)
                axes[0].set_yscale('log')
                axes[0].set_ylabel('Time (ms, log scale)')
                axes[0].set_xlabel('')
                axes[0].tick_params(axis='x', rotation=30)
                plt.setp(axes[0].get_xticklabels(), ha='right')
                axes[0].legend(title='Operation', loc='upper right')

            size_data = kem_data.melt(id_vars=['Display Family', 'Algorithm'], value_vars=size_metrics, var_name='Metric', value_name='Size (bytes)')
            if not size_data.empty:
                sns.boxplot(data=size_data, x='Display Family', y='Size (bytes)', hue='Metric', palette='Set2', ax=axes[1], showfliers=False)
                axes[1].set_yscale('log')
                axes[1].set_ylabel('Size (bytes, log scale)')
                axes[1].set_xlabel('Algorithm Family')
                axes[1].tick_params(axis='x', rotation=30)
                plt.setp(axes[1].get_xticklabels(), ha='right')
                axes[1].legend(title='Metric', loc='upper right')

            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            plt.savefig(self.output_dir / 'figures' / 'kem_family_analysis.pdf')
            plt.close()

            # KEM Family Summary Table - use Display Family for consistent naming
            try:
                 # Group by display family for consistent table headers
                 kem_data_for_table = kem_data.copy()
                 kem_data_for_table['Family'] = kem_data_for_table['Display Family'] 
                 kem_family_summary = kem_data_for_table.groupby('Family')[metrics + size_metrics].agg(['mean', 'std', 'min', 'max']).round(2)
                 tex_path = self.output_dir / 'tables' / 'kem_family_summary.tex'
                 csv_path = self.output_dir / 'tables' / 'kem_family_summary.csv'
                 with open(tex_path, 'w') as f:
                     f.write(self._consolidated_df_to_latex(
                        kem_family_summary,
                        caption=f'KEM Family Summary Statistics ({ref_platform_upper})',
                        label='tab:kem_family_summary',
                        float_format='%.2f'
                    ))
                 kem_family_summary.reset_index().to_csv(csv_path, index=False, float_format='%.2f') # Save CSV
            except Exception as e:
                 print(f"Warning: Could not generate KEM family summary table: {e}")


        if not sig_data.empty:
            message_sizes = sorted(sig_data['Message Size (bytes)'].unique())
            if message_sizes:
                 msg_size_example = message_sizes[len(message_sizes) // 2]
                 sig_data_example = sig_data[sig_data['Message Size (bytes)'] == msg_size_example]

                 if not sig_data_example.empty:
                     # Add display family for consistent labels
                     sig_data_example['Display Family'] = sig_data_example['Family'].map(lambda x: self.FAMILY_DISPLAY_MAP.get(x, x))
                     
                     sig_metrics = ['Key Generation (ms)', 'Signing (ms)', 'Verification (ms)']
                     sig_size_metrics = ['Public Key Size (bytes)', 'Signature Size (bytes)']

                     fig, axes = plt.subplots(2, 1, figsize=(11, 8), sharex=True)
                     fig.suptitle(f'Signature Family Comparison ({msg_size_example:,} Bytes, {ref_platform_upper})')

                     perf_data = sig_data_example.melt(id_vars=['Display Family', 'Algorithm'], value_vars=sig_metrics, var_name='Operation', value_name='Time (ms)')
                     if not perf_data.empty:
                         sns.boxplot(data=perf_data, x='Display Family', y='Time (ms)', hue='Operation', palette='Set2', ax=axes[0], showfliers=False)
                         axes[0].set_yscale('log')
                         axes[0].set_ylabel('Time (ms, log scale)')
                         axes[0].set_xlabel('')
                         axes[0].tick_params(axis='x', rotation=30)
                         plt.setp(axes[0].get_xticklabels(), ha='right')
                         axes[0].legend(title='Operation', loc='upper right')

                     size_data = sig_data_example.melt(id_vars=['Display Family', 'Algorithm'], value_vars=sig_size_metrics, var_name='Metric', value_name='Size (bytes)')
                     if not size_data.empty:
                         sns.boxplot(data=size_data, x='Display Family', y='Size (bytes)', hue='Metric', palette='Set2', ax=axes[1], showfliers=False)
                         axes[1].set_yscale('log')
                         axes[1].set_ylabel('Size (bytes, log scale)')
                         axes[1].set_xlabel('Algorithm Family')
                         axes[1].tick_params(axis='x', rotation=30)
                         plt.setp(axes[1].get_xticklabels(), ha='right')
                         axes[1].legend(title='Metric', loc='upper right')

                     plt.tight_layout(rect=[0, 0.03, 1, 0.95])
                     plt.savefig(self.output_dir / 'figures' / f'sig_family_analysis_{msg_size_example}.pdf')
                     plt.close()

                     # Signature Family Summary Table - use Display Family for consistent naming
                     try:
                         # Group by display family for consistent table headers
                         sig_data_for_table = sig_data_example.copy()
                         sig_data_for_table['Family'] = sig_data_for_table['Display Family']
                         sig_family_summary = sig_data_for_table.groupby('Family')[sig_metrics + sig_size_metrics].agg(['mean', 'std', 'min', 'max']).round(2)
                         tex_path = self.output_dir / 'tables' / f'sig_family_summary_{msg_size_example}.tex'
                         csv_path = self.output_dir / 'tables' / f'sig_family_summary_{msg_size_example}.csv'
                         with open(tex_path, 'w') as f:
                             f.write(self._consolidated_df_to_latex(
                                sig_family_summary,
                                caption=f'Signature Family Summary Statistics ({msg_size_example:,} Bytes, {ref_platform_upper})',
                                label=f'tab:sig_family_summary_{msg_size_example}',
                                float_format='%.2f'
                            ))
                         sig_family_summary.reset_index().to_csv(csv_path, index=False, float_format='%.2f') # Save CSV
                     except Exception as e:
                         print(f"Warning: Could not generate Sig family summary table (size {msg_size_example}): {e}")


    def generate_message_size_analysis(self):
        """Generate message size impact analysis using consolidated data."""
        print("  Generating message size figures and tables...")
        if not self.reference_platform_available:
             print("  Skipping message size analysis: Reference platform data unavailable.")
             return

        ref_platform_upper = self.REFERENCE_PLATFORM.upper()
        sig_data = self.platform_data['sig'][self.platform_data['sig']['Platform'] == ref_platform_upper]

        if sig_data.empty:
             print("  Skipping message size analysis: No signature data.")
             return

        # Add display family
        sig_data['Display Family'] = sig_data['Family'].map(lambda x: self.FAMILY_DISPLAY_MAP.get(x, x))

        # Filter to representative algorithms - limit to 2 per family instead of 3 for less crowded plots
        top_algs_by_family = {}
        try:
            for family in sig_data['Family'].unique():
                family_data = sig_data[sig_data['Family'] == family]
                algs = family_data.sort_values('Security Level', ascending=False)['Algorithm'].unique()
                top_algs_by_family[family] = algs[:min(2, len(algs))] # Take top 2 per family to reduce clutter
        except Exception as e:
            print(f"Warning: Error selecting top algorithms for message size plot: {e}")
            return # Cannot proceed without algorithms

        selected_algs = [alg for algs in top_algs_by_family.values() for alg in algs]
        filtered_data = sig_data[sig_data['Algorithm'].isin(selected_algs)]

        if filtered_data.empty:
             print("  Skipping message size analysis: No data after filtering algorithms.")
             return

        # --- Signing Time Plot ---
        plt.figure(figsize=(12, 7))
        try:
            # Use tab10 or tab20 palette for better visualization of different algorithms
            palette = sns.color_palette("tab20", len(selected_algs))
            markers = ['o', 's', 'D', '^', 'v', '<', '>', 'p', '*', 'X', 'd'] * ((len(selected_algs) // 11) + 1)

            plot_lines = [] # For custom legend handles if needed
            for i, (alg, alg_data) in enumerate(filtered_data.groupby('Algorithm')):
                family = alg_data['Display Family'].iloc[0]  # Use Display Family for consistent labels
                line = sns.lineplot(
                    data=alg_data, x='Message Size (bytes)', y='Signing (ms)',
                    marker=markers[i % len(markers)], markersize=6,
                    label=f"{alg} ({family})", # Include family in label
                    linewidth=1.5, alpha=0.8, color=palette[i % len(palette)]
                )
                if line: plot_lines.append(line) # Collect handles/labels if needed

            if not plot_lines: # Check if any lines were actually plotted
                 print("Warning: No lines were plotted for signing time vs message size.")
                 plt.close() # Close empty figure
                 return

            plt.xscale('log')
            plt.yscale('log')
            plt.title(f'Signing Time vs Message Size ({ref_platform_upper})')
            plt.xlabel('Message Size (bytes, log scale)')
            plt.ylabel('Signing Time (ms, log scale)')
            plt.grid(True, alpha=0.3, linestyle='--')
            
            # Use smaller font size for legend to prevent overlap and increase bbox width
            plt.legend(title="Algorithm (Family)", fontsize=7, title_fontsize=8,
                       bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0)
            plt.tight_layout(rect=[0, 0, 0.8, 1]) # Wider space for legend
            plt.savefig(self.output_dir / 'figures' / 'msg_size_impact_signing.pdf')
            plt.close()
        except Exception as e:
            print(f"Error generating signing time vs message size plot: {e}")
            plt.close() # Ensure figure is closed on error

        # --- Verification Time Plot ---
        plt.figure(figsize=(12, 7))
        try:
            # Use tab10 or tab20 palette for better visualization
            palette = sns.color_palette("tab20", len(selected_algs))
            markers = ['o', 's', 'D', '^', 'v', '<', '>', 'p', '*', 'X', 'd'] * ((len(selected_algs) // 11) + 1)

            plot_lines = []
            for i, (alg, alg_data) in enumerate(filtered_data.groupby('Algorithm')):
                family = alg_data['Display Family'].iloc[0]  # Use Display Family for consistent labels
                line = sns.lineplot(
                    data=alg_data, x='Message Size (bytes)', y='Verification (ms)',
                    marker=markers[i % len(markers)], markersize=6,
                    label=f"{alg} ({family})",
                    linewidth=1.5, alpha=0.8, color=palette[i % len(palette)]
                )
                if line: plot_lines.append(line)

            if not plot_lines:
                 print("Warning: No lines were plotted for verification time vs message size.")
                 plt.close()
                 return

            plt.xscale('log')
            plt.yscale('log')
            plt.title(f'Verification Time vs Message Size ({ref_platform_upper})')
            plt.xlabel('Message Size (bytes, log scale)')
            plt.ylabel('Verification Time (ms, log scale)')
            plt.grid(True, alpha=0.3, linestyle='--')
            
            # Use smaller font size for legend to prevent overlap and increase bbox width
            plt.legend(title="Algorithm (Family)", fontsize=7, title_fontsize=8,
                       bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0)
            plt.tight_layout(rect=[0, 0, 0.8, 1]) # Wider space for legend
            plt.savefig(self.output_dir / 'figures' / 'msg_size_impact_verify.pdf')
            plt.close()
        except Exception as e:
            print(f"Error generating verification time vs message size plot: {e}")
            plt.close()


    def generate_resource_requirements_plot(self):
        """Generate Time vs Memory plot for resource-constrained platform."""
        print("  Generating resource requirements plot...")
        if not self.resource_platform_available:
            print(f"  Skipping resource plot: {self.RESOURCE_PLATFORM} data unavailable.")
            return

        res_platform_upper = self.RESOURCE_PLATFORM.upper()
        kem_data_original = self.platform_data['kem'][self.platform_data['kem']['Platform'] == res_platform_upper]
        sig_data_original = self.platform_data['sig'][self.platform_data['sig']['Platform'] == res_platform_upper]

        # --- KEM Resource Plot ---
        if not kem_data_original.empty:
            kem_data = kem_data_original.copy()
            kem_data['Total Time (ms)'] = kem_data['Key Generation (ms)'] + kem_data['Encapsulation (ms)'] + kem_data['Decapsulation (ms)']
            kem_data['Memory Overhead (bytes)'] = kem_data['Public Key Size (bytes)'] + kem_data['Ciphertext Size (bytes)']
            # Add display family
            kem_data['Display Family'] = kem_data['Family'].map(lambda x: self.FAMILY_DISPLAY_MAP.get(x, x))
            # Filter out invalid data points
            kem_data = kem_data[(kem_data['Total Time (ms)'] > 0) & (kem_data['Memory Overhead (bytes)'] > 0)]

            if not kem_data.empty:
                plt.figure(figsize=(10, 7))
                ax_kem = sns.scatterplot( # Get axes
                    data=kem_data, x='Total Time (ms)', y='Memory Overhead (bytes)',
                    hue='Display Family', style='Security Level', size='Security Level',
                    sizes=(40, 200), alpha=0.8, palette='tab10', legend='full'
                )
                plt.xscale('log')
                plt.yscale('log')
                plt.title(f'KEM Resource Requirements ({res_platform_upper})')
                plt.xlabel('Total Operation Time (ms, log scale)')
                plt.ylabel('Comm./Storage Overhead (bytes, log scale)')
                plt.grid(True, which="both", ls="--", alpha=0.3)

                # --- adjustText for KEM Resource Plot ---
                texts_kem = []
                for i, point in kem_data.iterrows():
                     label_text = point['Algorithm']
                     should_label = False
                     # More strict criteria for labeling & specific handling
                     if point['Family'] == 'Code': 
                         if point['Algorithm'] == 'Classic-McEliece-6960119': should_label = True
                     elif point['Family'] == 'FrodoKEM':
                         if point['Algorithm'] == 'FrodoKEM-1344-SHAKE': should_label = True
                     elif (point['Security Level'] >= 5 or 
                         point['Memory Overhead (bytes)'] > 300000 or 
                         point['Total Time (ms)'] > 5000): # Increased time threshold
                         should_label = True
                         
                     if should_label:
                          texts_kem.append(plt.text(point['Total Time (ms)'], point['Memory Overhead (bytes)'],
                                           label_text, fontsize=5)) # Reduced fontsize
                if texts_kem:
                    adjust_text(texts_kem, ax=ax_kem, 
                                arrowprops=dict(arrowstyle='-', color='gray', lw=0.5, alpha=0.6),
                                expand_points=(1.8, 1.8),
                                force_text=(0.8, 0.8), 
                                force_points=(0.6, 0.6))
                # --- End adjustText ---

                plt.legend(title='Family / Sec Level', bbox_to_anchor=(1.05, 1), loc='upper left')
                plt.tight_layout(rect=[0, 0, 0.82, 1])
                plt.savefig(self.output_dir / 'figures' / 'kem_resource_req.pdf')
                plt.close()
            else:
                print("  Skipping KEM resource plot: No valid data points after filtering.")

        # --- Signature Resource Plot ---
        if not sig_data_original.empty:
            message_sizes = sorted(sig_data_original['Message Size (bytes)'].unique())
            if message_sizes:
                 msg_size_example = message_sizes[len(message_sizes) // 2]
                 sig_data_slice = sig_data_original[sig_data_original['Message Size (bytes)'] == msg_size_example]

                 if not sig_data_slice.empty:
                     sig_data_example = sig_data_slice.copy()
                     sig_data_example['Total Time (ms)'] = sig_data_example['Key Generation (ms)'] + sig_data_example['Signing (ms)'] + sig_data_example['Verification (ms)']
                     sig_data_example['Memory Overhead (bytes)'] = sig_data_example['Public Key Size (bytes)'] + sig_data_example['Signature Size (bytes)']
                     # Add display family using consistent mapping
                     sig_data_example['Display Family'] = sig_data_example['Family'].map(lambda x: self.FAMILY_DISPLAY_MAP.get(x, x))
                     # Filter invalid points
                     sig_data_example = sig_data_example[(sig_data_example['Total Time (ms)'] > 0) & (sig_data_example['Memory Overhead (bytes)'] > 0)]

                     if not sig_data_example.empty:
                         plt.figure(figsize=(10, 7))
                         ax_sig = sns.scatterplot( # Get axes
                            data=sig_data_example, x='Total Time (ms)', y='Memory Overhead (bytes)',
                            hue='Display Family', style='Security Level', size='Security Level',
                            sizes=(40, 200), alpha=0.8, palette='tab10', legend='full'
                         )
                         plt.xscale('log')
                         plt.yscale('log')
                         plt.title(f'Signature Resource Requirements ({msg_size_example:,} Bytes, {res_platform_upper})')
                         plt.xlabel('Total Operation Time (ms, log scale)')
                         plt.ylabel('Comm./Storage Overhead (bytes, log scale)')
                         plt.grid(True, which="both", ls="--", alpha=0.3)

                         # --- adjustText for Signature Resource Plot ---
                         texts_sig = []
                         labeled_sphincs = 0 # Counter for SPHINCS labels
                         max_sphincs_labels = 2 # Limit SPHINCS labels
                         
                         for i, point in sig_data_example.iterrows():
                             label_text = point['Algorithm']
                             should_label = False
                             # Apply general strict criteria first
                             if (point['Security Level'] >= 5 or 
                                 point['Memory Overhead (bytes)'] > 50000 or 
                                 point['Total Time (ms)'] > 5000):
                              should_label = True
                         
                             # Special handling for SPHINCS+ to reduce clutter
                             if point['Family'] == 'Hash': # Hash-based (SPHINCS+)
                                 if should_label and labeled_sphincs < max_sphincs_labels: 
                                     # Only label if it met general criteria AND we haven't hit the SPHINCS label limit
                                     labeled_sphincs += 1
                                 else:
                                     should_label = False # Don't label other SPHINCS+ even if they met general criteria
                                 
                             if should_label:
                                 texts_sig.append(plt.text(point['Total Time (ms)'], point['Memory Overhead (bytes)'],
                                          label_text, fontsize=5)) 
                         if texts_sig:
                             adjust_text(texts_sig, ax=ax_sig, 
                                         arrowprops=dict(arrowstyle='-', color='gray', lw=0.5, alpha=0.5), # Slightly fainter arrows
                                         expand_points=(2.0, 2.0), # Increased expansion further
                                         force_text=(1.0, 1.0), # Increased force further
                                         force_points=(0.7, 0.7))
                         # --- End adjustText ---

                         plt.legend(title='Family / Sec Level', bbox_to_anchor=(1.05, 1), loc='upper left')
                         plt.tight_layout(rect=[0, 0, 0.82, 1])
                         plt.savefig(self.output_dir / 'figures' / f'sig_resource_req_{msg_size_example}.pdf')
                         plt.close()
                     else:
                          print(f"  Skipping Sig resource plot (size {msg_size_example}): No valid data points after filtering.")
                 else:
                     print(f"  Skipping Sig resource plot: No data for median message size {msg_size_example}.")
            else:
                 print("  Skipping Sig resource plot: No message sizes found in data.")
        else:
            print("  Skipping Sig resource plot: No signature data for resource platform.")


    # --- Main Execution ---
    def run_analysis(self):
        """Run the full consolidated analysis pipeline."""
        if self.platform_data['kem'].empty and self.platform_data['sig'].empty:
            print("No data loaded after processing. Cannot run analysis.")
            return

        self.generate_platform_comparison()
        self.generate_communication_analysis()
        self.generate_security_analysis()
        self.generate_family_analysis()
        self.generate_message_size_analysis()
        self.generate_resource_requirements_plot()

        print(f"\nConsolidated analysis complete. Results saved in {self.output_dir}")

def main():
    """Main execution function"""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description='Generate consolidated analysis of PQC benchmarks, handling duplicates.'
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
            'text.latex.preamble': '',
            'pgf.texsystem': None,
            'pgf.rcfonts': None,
        })
        print("LaTeX rendering disabled.")

    try:
        analyzer = ConsolidatedAnalyzer(args.results_dir)
        analyzer.run_analysis()
    except FileNotFoundError as e:
        print(f"Error: Input directory not found or missing files. {e}", file=sys.stderr)
        sys.exit(1)
    except ImportError as e:
         if 'adjustText' in str(e):
              print("Error: adjustText library not found. Please install it: pip install adjustText", file=sys.stderr)
         else:
              print(f"Error: Import error: {e}", file=sys.stderr)
         sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during analysis: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()