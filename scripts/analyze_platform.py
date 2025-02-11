#!/usr/bin/env python3
"""
Analysis of post-quantum cryptography benchmarks for platform-specific analysis.
Generates plots and tables focusing on:
1. Algorithm Performance Comparison
2. Security Level Analysis
3. Communication Overhead Analysis
"""

import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import matplotlib as mpl

# Set up matplotlib for publication quality
plt.style.use(['seaborn-v0_8-paper'])
mpl.rcParams.update({
    'font.family': 'serif',
    'text.usetex': True,
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
})

class PlatformAnalyzer:
    # Algorithm family definitions with correct categorizations
    KEM_FAMILIES = {
        'Lattice-based': ['Kyber', 'ML-KEM', 'FrodoKEM'],
        'Code-based': ['Classic-McEliece', 'BIKE', 'HQC'],
        'NTRU': ['NTRU', 'sntrup', 'ntruprime'],
        'Classical': ['RSA', 'ECDH']
    }
    
    SIGNATURE_FAMILIES = {
        'Lattice-based': ['Dilithium', 'ML-DSA', 'Falcon'], 
        'Hash-based': ['SPHINCS+'],
        'Multivariate': ['MAYO', 'Rainbow'],
        'RSDP': ['cross-rsdp', 'cross-rsdpg'],
        'Classical': ['RSA', 'ECDSA', 'Ed25519']
    }
    
    def __init__(self, results_base: Path, platform: str = 'macos'):
        """Initialize analyzer with base results directory and platform"""
        self.results_base = results_base
        self.platform = platform
        self.output_dir = results_base / 'analysis' / platform
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / 'plots').mkdir(exist_ok=True)
        (self.output_dir / 'tables').mkdir(exist_ok=True)
        
        # Load platform results
        self.results = self.load_platform_results()
    
    def load_platform_results(self) -> dict:
        """
        Load results for the specified platform from the most recent experiment.
        
        Returns:
            dict: Dictionary containing configuration and results data
                 with keys 'config', 'pqc', and 'baseline'
                 
        Raises:
            FileNotFoundError: If platform directory or result files not found
            RuntimeError: If there's an error loading the result files
        """
        platform_dir = self.results_base / self.platform
        if not platform_dir.exists():
            raise FileNotFoundError(f"No results directory found for {self.platform}")
            
        # Get most recent results directory
        result_dirs = sorted(platform_dir.glob('*'))
        if not result_dirs:
            raise FileNotFoundError(f"No result directories found in {platform_dir}")
            
        latest_dir = result_dirs[-1]
        print(f"Loading {self.platform} results from {latest_dir}")
        
        try:
            # Load configuration
            with open(latest_dir / 'experiment_config.json') as f:
                config = json.load(f)
            
            # Load PQC results
            with open(latest_dir / 'pqc' / 'pqc_metrics.json') as f:
                pqc_results = json.load(f)
            
            # Load baseline results
            with open(latest_dir / 'baseline' / 'baseline_metrics.json') as f:
                baseline_results = json.load(f)
            
            # Validate loaded data
            self._validate_results(pqc_results, baseline_results)
            
            return {
                'config': config,
                'pqc': pqc_results,
                'baseline': baseline_results
            }
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Error decoding JSON from result files: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Error loading results: {str(e)}")

    def _validate_results(self, pqc_results: dict, baseline_results: dict) -> None:
        """
        Validate the structure and content of loaded results.
        
        Args:
            pqc_results: Dictionary containing PQC benchmark results
            baseline_results: Dictionary containing baseline benchmark results
            
        Raises:
            ValueError: If required data is missing or malformed
        """
        required_sections = ['results']
        required_types = ['kems', 'signatures']
        
        for results in [pqc_results, baseline_results]:
            if not all(section in results for section in required_sections):
                raise ValueError("Missing required sections in results")
                
            if not all(type_ in results['results'] for type_ in required_types):
                raise ValueError("Missing required algorithm types in results")

    def get_nist_level(self, alg_name: str, details: dict) -> int:
        """
        Get NIST security level for an algorithm.
        
        Args:
            alg_name: Name of the algorithm
            details: Dictionary containing algorithm details
            
        Returns:
            int: NIST security level (1, 3, or 5)
        """
        if 'claimed_nist_level' in details:
            return details['claimed_nist_level']
        
        # For classical algorithms, estimate based on key size
        if 'RSA' in alg_name:
            key_size = int(alg_name.split('-')[-1])
            if key_size <= 2048: return 1
            if key_size <= 3072: return 3
            return 5
        
        if 'ECDSA' in alg_name or 'ECDH' in alg_name:
            key_size = int(alg_name.split('-')[-1])
            if key_size <= 256: return 1
            if key_size <= 384: return 3
            return 5
            
        return 1  # Default for unknown algorithms
    
    def prepare_kem_data(self) -> pd.DataFrame:
        """
        Prepare KEM data for analysis. Processes both PQC and classical KEM results
        into a standardized DataFrame format.
        
        Returns:
            pd.DataFrame: Processed KEM data with performance and size metrics
        """
        records = []
        
        # Process PQC KEMs
        for name, data in self.results['pqc']['results']['kems'].items():
            record = {
                'Algorithm': name,
                'Type': 'Post-Quantum',
                'Security Level': self.get_nist_level(name, data['algorithm_details']),
                # Performance metrics
                'Key Generation (ms)': data['statistics']['key_generation']['mean_ms'],
                'Key Gen Std (ms)': data['statistics']['key_generation']['std_ms'],
                'Encapsulation (ms)': data['statistics']['encapsulation']['mean_ms'],
                'Encap Std (ms)': data['statistics']['encapsulation']['std_ms'],
                'Decapsulation (ms)': data['statistics']['decapsulation']['mean_ms'],
                'Decap Std (ms)': data['statistics']['decapsulation']['std_ms'],
                # Size metrics
                'Public Key Size (bytes)': data['sizes']['public_key'],
                'Secret Key Size (bytes)': data.get('sizes', {}).get('secret_key', 0),
                'Ciphertext Size (bytes)': data['sizes']['ciphertext'],
                'Shared Secret Size (bytes)': data['sizes']['shared_secret'],
            }
            records.append(record)
        
        # Process classical KEMs
        for name, data in self.results['baseline']['results']['kems'].items():
            record = {
                'Algorithm': name,
                'Type': 'Classical',
                'Security Level': self.get_nist_level(name, data.get('algorithm_details', {})),
                # Performance metrics
                'Key Generation (ms)': data['statistics']['key_generation']['mean_ms'],
                'Key Gen Std (ms)': data['statistics']['key_generation']['std_ms'],
                'Encapsulation (ms)': data['statistics']['encapsulation']['mean_ms'],
                'Encap Std (ms)': data['statistics']['encapsulation']['std_ms'],
                'Decapsulation (ms)': data['statistics']['decapsulation']['mean_ms'],
                'Decap Std (ms)': data['statistics']['decapsulation']['std_ms'],
                # Size metrics
                'Public Key Size (bytes)': data['sizes']['public_key'],
                'Secret Key Size (bytes)': data.get('sizes', {}).get('secret_key', 0),
                'Ciphertext Size (bytes)': data['sizes']['ciphertext'],
                'Shared Secret Size (bytes)': data['sizes']['shared_secret'],
            }
            records.append(record)
        
        df = pd.DataFrame(records)
        df['Family'] = df['Algorithm'].apply(lambda x: x.split('-')[0] if '-' in x else x)
        return df

    def prepare_signature_data(self) -> pd.DataFrame:
        """
        Prepare signature data for analysis. Processes both PQC and classical signature
        results into a standardized DataFrame format, including message size variations.
        
        Returns:
            pd.DataFrame: Processed signature data with performance and size metrics
                        for different message sizes
        """
        records = []
        
        # Process PQC signatures
        for name, data in self.results['pqc']['results']['signatures'].items():
            base_record = {
                'Algorithm': name,
                'Type': 'Post-Quantum',
                'Security Level': self.get_nist_level(name, data['algorithm_details']),
                # Key Generation Performance
                'Key Generation (ms)': data['statistics']['key_generation']['mean_ms'],
                'Key Gen Std (ms)': data['statistics']['key_generation']['std_ms'],
                # Key Sizes
                'Public Key Size (bytes)': data['sizes']['public_key'],
                'Secret Key Size (bytes)': data.get('sizes', {}).get('secret_key', 0),
            }
            
            # Add records for each message size
            for msg_size in data['statistics']['signing'].keys():
                record = base_record.copy()
                record.update({
                    'Message Size (bytes)': int(msg_size),
                    # Signing Performance
                    'Signing (ms)': data['statistics']['signing'][msg_size]['mean_ms'],
                    'Sign Std (ms)': data['statistics']['signing'][msg_size]['std_ms'],
                    'Verification (ms)': data['statistics']['verification'][msg_size]['mean_ms'],
                    'Verify Std (ms)': data['statistics']['verification'][msg_size]['std_ms'],
                    # Signature Size
                    'Signature Size (bytes)': data['sizes'][f'signature_{msg_size}'],
                })
                records.append(record)
        
        # Process classical signatures
        for name, data in self.results['baseline']['results']['signatures'].items():
            base_record = {
                'Algorithm': name,
                'Type': 'Classical',
                'Security Level': self.get_nist_level(name, data.get('algorithm_details', {})),
                'Key Generation (ms)': data['statistics']['key_generation']['mean_ms'],
                'Key Gen Std (ms)': data['statistics']['key_generation']['std_ms'],
                'Public Key Size (bytes)': data['sizes']['public_key'],
                'Secret Key Size (bytes)': data.get('sizes', {}).get('secret_key', 0),
            }
            
            for msg_size in data['statistics']['signing'].keys():
                record = base_record.copy()
                record.update({
                    'Message Size (bytes)': int(msg_size),
                    'Signing (ms)': data['statistics']['signing'][msg_size]['mean_ms'],
                    'Sign Std (ms)': data['statistics']['signing'][msg_size]['std_ms'],
                    'Verification (ms)': data['statistics']['verification'][msg_size]['mean_ms'],
                    'Verify Std (ms)': data['statistics']['verification'][msg_size]['std_ms'],
                    'Signature Size (bytes)': data['sizes'][f'signature_{msg_size}'],
                })
                records.append(record)
        
        df = pd.DataFrame(records)
        df['Family'] = df['Algorithm'].apply(lambda x: x.split('-')[0] if '-' in x else x)
        return df
    
    @staticmethod
    def format_value(x: float) -> str:
        """Format values for plot labels based on magnitude."""
        if x >= 100:
            return f'{x:.0f}'
        elif x >= 10:
            return f'{x:.1f}'
        else:
            return f'{x:.2f}'
    
    def setup_plot_style(self, figsize=(12, 8)) -> None:
        """Set up common plot style settings."""
        plt.figure(figsize=figsize)
        plt.grid(True, which="both", ls="-", alpha=0.2)
    
    def add_value_labels(self, g, fontsize=7, padding=2) -> None:
        """Add value labels to bar plots."""
        for container in g.containers:
            labels = [self.format_value(v) for v in container.datavalues]
            g.bar_label(container, 
                       labels=labels,
                       label_type='edge',
                       rotation=0,
                       fontsize=fontsize,
                       padding=padding)
    
    def adjust_plot_layout(self, title: str, adjust_top=0.88) -> None:
        """Apply common layout adjustments to plots."""
        plt.title(title)
        plt.ylabel('Time (ms)')
        plt.xlabel('')
        plt.xticks(rotation=45, ha='right')
        plt.legend(
            title='Operation',
            bbox_to_anchor=(1.05, 1),
            loc='upper left',
            borderaxespad=0,
            fontsize=8
        )
        plt.tight_layout()
        plt.subplots_adjust(top=adjust_top, right=0.85, bottom=0.2)

    def create_performance_plot(self, data: pd.DataFrame, title: str, 
                              filename: str, adjust_top=0.88) -> None:
        """Create a performance comparison bar plot."""
        g = sns.barplot(
            data=data,
            x='Algorithm',
            y='value',
            hue='variable',
            palette='husl',
            width=0.8
        )
        
        plt.yscale('log')
        # Adjust y-axis limits to accommodate labels
        ymin, ymax = plt.ylim()
        plt.ylim(ymin, ymax * 2)
        
        self.add_value_labels(g)
        self.adjust_plot_layout(title, adjust_top)
        
        plt.savefig(
            self.output_dir / 'plots' / filename,
            bbox_inches='tight',
            pad_inches=0.2,
            dpi=300
        )
        plt.close()

    def plot_performance_comparisons(self, kem_df: pd.DataFrame, sig_df: pd.DataFrame):
        """Generate comprehensive performance comparison plots."""
        performance_metrics = ['Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)']
        
        # KEM Performance by Family
        for family_name, prefixes in self.KEM_FAMILIES.items():
            family_data = kem_df[
                kem_df['Algorithm'].apply(
                    lambda x: any(x.startswith(prefix) for prefix in prefixes)
                )
            ]
            
            if len(family_data) == 0:
                continue
            
            # Melt the data for plotting
            family_perf = family_data.melt(
                id_vars=['Algorithm', 'Type', 'Security Level'],
                value_vars=performance_metrics
            )
            
            self.setup_plot_style(figsize=(14, 9))
            self.create_performance_plot(
                family_perf,
                f'{family_name} KEM Performance ({self.platform.upper()})',
                f'kem_performance_{family_name.lower().replace("-", "_")}.pdf'
            )
        
        # KEM Summary Plot with representative algorithms
        summary_algorithms = {
            'ML-KEM-768': 'Lattice-based',
            'Classic-McEliece-460896': 'Code-based',
            'sntrup761': 'NTRU',
            'RSA-3072': 'Classical',
            'ECDH-384': 'Classical ECC'
        }
        
        summary_data = kem_df[kem_df['Algorithm'].isin(summary_algorithms.keys())].melt(
            id_vars=['Algorithm', 'Type', 'Security Level'],
            value_vars=performance_metrics
        )
        
        self.setup_plot_style(figsize=(14, 9))
        self.create_performance_plot(
            summary_data,
            f'Summary: KEM Performance Comparison ({self.platform.upper()})',
            'kem_performance_summary.pdf',
            adjust_top=0.85
        )
        
        # Signature Performance by Family
        for family_name, prefixes in self.SIGNATURE_FAMILIES.items():
            family_data = sig_df[
                sig_df['Algorithm'].apply(
                    lambda x: any(x.startswith(prefix) for prefix in prefixes)
                )
            ]
            
            if len(family_data) == 0:
                continue
            
            self.setup_plot_style()
            sns.lineplot(
                data=family_data,
                x='Message Size (bytes)',
                y='Signing (ms)',
                hue='Algorithm',
                style='Type',
                markers=True,
                dashes=False
            )
            
            plt.xscale('log')
            plt.yscale('log')
            plt.title(f'{family_name} Signature Performance vs Message Size ({self.platform.upper()})')
            plt.xlabel('Message Size (bytes)')
            plt.ylabel('Signing Time (ms)')
            plt.legend(
                bbox_to_anchor=(1.05, 1),
                loc='upper left',
                borderaxespad=0,
                fontsize=8,
                title='Algorithm'
            )
            plt.tight_layout()
            plt.savefig(
                self.output_dir / 'plots' / f'signature_performance_{family_name.lower().replace("-", "_")}.pdf',
                bbox_inches='tight',
                dpi=300
            )
            plt.close()
        
        # Signature Summary Plot
        summary_algorithms = {
            'ML-DSA-65': 'Lattice-based',
            'SPHINCS+-SHA2-256f-simple': 'Hash-based',
            'MAYO-3': 'Multivariate',
            'cross-rsdp-256-balanced': 'RSDP',
            'RSA-3072': 'Classical',
            'ECDSA-384': 'Classical ECC'
        }
        
        summary_data = sig_df[sig_df['Algorithm'].isin(summary_algorithms.keys())]
        
        self.setup_plot_style(figsize=(14, 8))
        sns.lineplot(
            data=summary_data,
            x='Message Size (bytes)',
            y='Signing (ms)',
            hue='Algorithm',
            style='Type',
            markers=True,
            dashes=False,
            linewidth=2
        )
        
        plt.xscale('log')
        plt.yscale('log')
        plt.title(f'Summary: Signature Performance Comparison ({self.platform.upper()})')
        plt.xlabel('Message Size (bytes)')
        plt.ylabel('Signing Time (ms)')
        plt.legend(
            bbox_to_anchor=(1.05, 1),
            loc='upper left',
            borderaxespad=0,
            fontsize=8,
            title='Algorithm'
        )
        plt.tight_layout()
        plt.savefig(
            self.output_dir / 'plots' / 'signature_performance_summary.pdf',
            bbox_inches='tight',
            dpi=300
        )
        plt.close()

    def plot_security_analysis(self, kem_df: pd.DataFrame, sig_df: pd.DataFrame):
        """Generate security level analysis plots with consistent formatting."""
        # Common plot parameters for security analysis
        security_plot_params = {
            'figsize': (12, 8),
            'palette': 'husl',
            'legend_title': 'Type',
            'x_label': 'NIST Security Level',
        }

        # KEM Security Level Analysis
        self.setup_plot_style(figsize=security_plot_params['figsize'])
        
        # Create aggregated data for better visualization
        kem_security_data = kem_df.melt(
            id_vars=['Security Level', 'Type', 'Algorithm'],
            value_vars=['Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)'],
            var_name='Operation',
            value_name='Time (ms)'
        )
        
        g = sns.boxplot(
            data=kem_security_data,
            x='Security Level',
            y='Time (ms)',
            hue='Type',
            palette=security_plot_params['palette']
        )
        
        plt.yscale('log')
        plt.title(f'KEM Performance by Security Level ({self.platform.upper()})')
        plt.xlabel(security_plot_params['x_label'])
        plt.ylabel('Time (ms)')
        
        # Add statistical annotations
        for i, level in enumerate(sorted(kem_df['Security Level'].unique())):
            level_data = kem_security_data[kem_security_data['Security Level'] == level]
            plt.text(i, plt.ylim()[0] * 1.1, f'n={len(level_data)}', 
                    ha='center', va='bottom', fontsize=8)
        
        plt.legend(
            title=security_plot_params['legend_title'],
            bbox_to_anchor=(1.05, 1),
            loc='upper left',
            borderaxespad=0
        )
        
        plt.tight_layout()
        plt.savefig(
            self.output_dir / 'plots' / 'kem_security.pdf',
            bbox_inches='tight',
            pad_inches=0.2,
            dpi=300
        )
        plt.close()
        
        # Signature Security Level Analysis
        self.setup_plot_style(figsize=security_plot_params['figsize'])
        
        # Create aggregated data for signatures
        sig_security_data = sig_df.melt(
            id_vars=['Security Level', 'Type', 'Algorithm'],
            value_vars=['Signing (ms)', 'Verification (ms)'],
            var_name='Operation',
            value_name='Time (ms)'
        )
        
        g = sns.boxplot(
            data=sig_security_data,
            x='Security Level',
            y='Time (ms)',
            hue='Type',
            palette=security_plot_params['palette']
        )
        
        plt.yscale('log')
        plt.title(f'Signature Performance by Security Level ({self.platform.upper()})')
        plt.xlabel(security_plot_params['x_label'])
        plt.ylabel('Time (ms)')
        
        # Add statistical annotations
        for i, level in enumerate(sorted(sig_df['Security Level'].unique())):
            level_data = sig_security_data[sig_security_data['Security Level'] == level]
            plt.text(i, plt.ylim()[0] * 1.1, f'n={len(level_data)}', 
                    ha='center', va='bottom', fontsize=8)
        
        plt.legend(
            title=security_plot_params['legend_title'],
            bbox_to_anchor=(1.05, 1),
            loc='upper left',
            borderaxespad=0
        )
        
        plt.tight_layout()
        plt.savefig(
            self.output_dir / 'plots' / 'signature_security.pdf',
            bbox_inches='tight',
            pad_inches=0.2,
            dpi=300
        )
        plt.close()

    def plot_communication_analysis(self, kem_df: pd.DataFrame, sig_df: pd.DataFrame):
        """Generate communication overhead analysis plots with enhanced visualization."""
        # Common parameters for communication plots
        comm_plot_params = {
            'figsize': (12, 8),
            'palette': 'husl',
            'size_range': (50, 200),
            'alpha': 0.7
        }

        # KEM Communication Overhead
        self.setup_plot_style(figsize=comm_plot_params['figsize'])
        
        g = sns.scatterplot(
            data=kem_df,
            x='Public Key Size (bytes)',
            y='Ciphertext Size (bytes)',
            hue='Type',
            style='Security Level',
            size='Security Level',
            sizes=comm_plot_params['size_range'],
            alpha=comm_plot_params['alpha'],
            palette=comm_plot_params['palette']
        )
        
        # Add algorithm labels for notable points
        for idx, row in kem_df.iterrows():
            if row['Type'] == 'Post-Quantum' and row['Security Level'] >= 3:
                plt.annotate(
                    row['Algorithm'].split('-')[0],
                    (row['Public Key Size (bytes)'], row['Ciphertext Size (bytes)']),
                    xytext=(5, 5),
                    textcoords='offset points',
                    fontsize=7,
                    alpha=0.7
                )
        
        plt.xscale('log')
        plt.yscale('log')
        plt.title(f'KEM Communication Overhead ({self.platform.upper()})')
        plt.xlabel('Public Key Size (bytes)')
        plt.ylabel('Ciphertext Size (bytes)')
        
        # Add reference lines for size thresholds
        plt.axhline(y=1024, color='gray', linestyle='--', alpha=0.3)
        plt.axvline(x=1024, color='gray', linestyle='--', alpha=0.3)
        
        plt.legend(
            bbox_to_anchor=(1.05, 1),
            loc='upper left',
            borderaxespad=0
        )
        
        plt.tight_layout()
        plt.savefig(
            self.output_dir / 'plots' / 'kem_overhead.pdf',
            bbox_inches='tight',
            pad_inches=0.2,
            dpi=300
        )
        plt.close()

        # Signature Communication Overhead
        self.setup_plot_style(figsize=comm_plot_params['figsize'])
        
        # Use average signature size for different message sizes
        sig_df_avg = sig_df.groupby(['Algorithm', 'Type', 'Security Level', 'Public Key Size (bytes)'])['Signature Size (bytes)'].mean().reset_index()
        
        g = sns.scatterplot(
            data=sig_df_avg,
            x='Public Key Size (bytes)',
            y='Signature Size (bytes)',
            hue='Type',
            style='Security Level',
            size='Security Level',
            sizes=comm_plot_params['size_range'],
            alpha=comm_plot_params['alpha'],
            palette=comm_plot_params['palette']
        )
        
        # Add algorithm labels for notable points
        for idx, row in sig_df_avg.iterrows():
            if row['Type'] == 'Post-Quantum' and row['Security Level'] >= 3:
                plt.annotate(
                    row['Algorithm'].split('-')[0],
                    (row['Public Key Size (bytes)'], row['Signature Size (bytes)']),
                    xytext=(5, 5),
                    textcoords='offset points',
                    fontsize=7,
                    alpha=0.7
                )
        
        plt.xscale('log')
        plt.yscale('log')
        plt.title(f'Signature Communication Overhead ({self.platform.upper()})')
        plt.xlabel('Public Key Size (bytes)')
        plt.ylabel('Average Signature Size (bytes)')
        
        # Add reference lines
        plt.axhline(y=1024, color='gray', linestyle='--', alpha=0.3)
        plt.axvline(x=1024, color='gray', linestyle='--', alpha=0.3)
        
        plt.legend(
            bbox_to_anchor=(1.05, 1),
            loc='upper left',
            borderaxespad=0
        )
        
        plt.tight_layout()
        plt.savefig(
            self.output_dir / 'plots' / 'signature_overhead.pdf',
            bbox_inches='tight',
            pad_inches=0.2,
            dpi=300
        )
        plt.close()
    
    def analyze_platform(self):
        """Run complete platform analysis with progress reporting."""
        print(f"Starting analysis for {self.platform}...")
        
        # Prepare data
        print("Preparing KEM data...")
        kem_df = self.prepare_kem_data()
        kem_df.to_csv(self.output_dir / 'processed_kem_data.csv', index=False)
        
        print("Preparing signature data...")
        sig_df = self.prepare_signature_data()
        sig_df.to_csv(self.output_dir / 'processed_signature_data.csv', index=False)
        
        # Generate plots
        print("Generating performance comparison plots...")
        self.plot_performance_comparisons(kem_df, sig_df)
        
        print("Generating security analysis plots...")
        self.plot_security_analysis(kem_df, sig_df)
        
        print("Generating communication overhead plots...")
        self.plot_communication_analysis(kem_df, sig_df)
        
        # Generate tables
        print("Generating LaTeX tables...")
        self.generate_latex_tables(kem_df, sig_df)
        
        print(f"Analysis complete.")

    def format_latex_table(self, df: pd.DataFrame, caption: str, label: str) -> str:
        """Helper method to format LaTeX tables consistently."""
        latex_str = df.to_latex(
            caption=caption,
            label=label,
            escape=False,
            longtable=True,
            multicolumn=True,
            multicolumn_format='c',
            column_format='l' + 'r' * (len(df.columns))
        )
        
        # Add booktabs style
        latex_str = latex_str.replace('\\begin{longtable}', '\\begin{longtable}\\toprule')
        latex_str = latex_str.replace('\\end{longtable}', '\\bottomrule\\end{longtable}')
        
        return latex_str

    def generate_latex_tables(self, kem_df: pd.DataFrame, sig_df: pd.DataFrame):
        """Generate publication-quality LaTeX tables with consistent formatting."""
        # KEM Performance Table
        kem_cols = ['Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)',
                   'Public Key Size (bytes)', 'Ciphertext Size (bytes)']
        kem_perf = pd.pivot_table(
            kem_df,
            index=['Algorithm', 'Type', 'Security Level'],
            values=kem_cols,
            aggfunc={
                'Key Generation (ms)': ['mean', 'std'],
                'Encapsulation (ms)': ['mean', 'std'],
                'Decapsulation (ms)': ['mean', 'std'],
                'Public Key Size (bytes)': 'first',
                'Ciphertext Size (bytes)': 'first'
            }
        ).round(2)
        
        # Sort by Type (Classical first) and Security Level
        kem_perf = kem_perf.reset_index().sort_values(
            ['Type', 'Security Level', 'Algorithm'],
            ascending=[True, True, True]
        ).set_index(['Algorithm', 'Type', 'Security Level'])
        
        caption = f'KEM Performance Analysis ({self.platform.upper()})'
        label = f'tab:kem_performance_{self.platform}'
        
        with open(self.output_dir / 'tables' / 'kem_performance.tex', 'w') as f:
            f.write(self.format_latex_table(kem_perf, caption, label))
        
        # Signature Performance Table
        sig_perf = pd.pivot_table(
            sig_df,
            index=['Algorithm', 'Type', 'Security Level'],
            columns='Message Size (bytes)',
            values=['Signing (ms)', 'Verification (ms)', 'Signature Size (bytes)'],
            aggfunc={
                'Signing (ms)': ['mean', 'std'],
                'Verification (ms)': ['mean', 'std'],
                'Signature Size (bytes)': 'first'
            }
        ).round(2)
        
        # Sort by Type and Security Level
        sig_perf = sig_perf.reset_index().sort_values(
            ['Type', 'Security Level', 'Algorithm'],
            ascending=[True, True, True]
        ).set_index(['Algorithm', 'Type', 'Security Level'])
        
        caption = f'Signature Performance Analysis ({self.platform.upper()})'
        label = f'tab:signature_performance_{self.platform}'
        
        with open(self.output_dir / 'tables' / 'signature_performance.tex', 'w') as f:
            f.write(self.format_latex_table(sig_perf, caption, label))
        
        # Security Level Impact Table
        security_impact = pd.concat([
            # KEM Security Impact
            kem_df.pivot_table(
                index='Security Level',
                columns='Type',
                values=['Key Generation (ms)', 'Public Key Size (bytes)', 'Ciphertext Size (bytes)'],
                aggfunc='mean'
            ),
            # Signature Security Impact
            sig_df.pivot_table(
                index='Security Level',
                columns='Type',
                values=['Signing (ms)', 'Verification (ms)', 'Signature Size (bytes)'],
                aggfunc='mean'
            )
        ]).round(2)
        
        caption = f'Security Level Impact Analysis ({self.platform.upper()})'
        label = f'tab:security_impact_{self.platform}'
        
        with open(self.output_dir / 'tables' / 'security_impact.tex', 'w') as f:
            f.write(self.format_latex_table(security_impact, caption, label))

def main():
    """Main function to run the platform analysis."""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(
        description='Analyze post-quantum cryptography benchmarks for specific platform.'
    )
    parser.add_argument(
        'platform',
        nargs='?',
        default='macos',
        choices=['macos', 'ubuntu', 'raspberry'],
        help='Platform to analyze (default: macos)'
    )
    parser.add_argument(
        '--results-dir',
        default='results',
        help='Base directory containing benchmark results (default: results)'
    )
    
    args = parser.parse_args()
    
    try:
        results_base = Path(args.results_dir)
        if not results_base.exists():
            raise FileNotFoundError(f"Results directory '{args.results_dir}' not found")
        
        analyzer = PlatformAnalyzer(results_base, args.platform)
        analyzer.analyze_platform()
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()