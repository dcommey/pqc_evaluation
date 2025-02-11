#!/usr/bin/env python3
"""
Cross-platform performance analysis of post-quantum cryptography benchmarks,
with special focus on constrained devices (Raspberry Pi).
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

class PlatformComparisonAnalyzer:
    """Analyzes performance differences across platforms with focus on constrained devices."""
    
    def __init__(self, results_base: Path):
        self.results_base = results_base
        self.output_dir = results_base / 'platform_analysis'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / 'figures').mkdir(exist_ok=True)
        (self.output_dir / 'tables').mkdir(exist_ok=True)
        
        # Load results
        self.platforms = ['macos', 'ubuntu', 'raspberry']
        self.results = self.load_all_results()
        self.platform_data = self.prepare_platform_data()

    def load_all_results(self) -> dict:
        """Load results from all platforms"""
        results = {}
        for platform in self.platforms:
            platform_dir = self.results_base / platform
            if not platform_dir.exists():
                continue
            
            # Get most recent results directory
            result_dirs = sorted(platform_dir.glob('*'))
            if not result_dirs:
                continue
                
            latest_dir = result_dirs[-1]
            print(f"Loading {platform} results from {latest_dir}")
            
            try:
                # Load PQC results
                with open(latest_dir / 'pqc' / 'pqc_metrics.json') as f:
                    pqc_results = json.load(f)
                
                # Load baseline results
                with open(latest_dir / 'baseline' / 'baseline_metrics.json') as f:
                    baseline_results = json.load(f)
                
                results[platform] = {
                    'pqc': pqc_results,
                    'baseline': baseline_results
                }
            except Exception as e:
                print(f"Error loading {platform} results: {str(e)}")
        
        return results

    def prepare_platform_data(self) -> dict:
        """Prepare data structures for all analyses"""
        platform_data = {
            'kem': {platform: [] for platform in self.platforms},
            'sig': {platform: [] for platform in self.platforms}
        }
        
        # Process each platform's data
        for platform, results in self.results.items():
            # Process KEM data
            for name, data in results['pqc']['results']['kems'].items():
                record = {
                    'Platform': platform.upper(),
                    'Algorithm': name,
                    'Type': 'Post-Quantum',
                    'Family': name.split('-')[0],
                    'Security Level': data['algorithm_details']['claimed_nist_level'],
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
                    'Shared Secret Size (bytes)': data['sizes']['shared_secret']
                }
                platform_data['kem'][platform].append(record)
            
            # Process classical KEMs
            for name, data in results['baseline']['results']['kems'].items():
                record = {
                    'Platform': platform.upper(),
                    'Algorithm': name,
                    'Type': 'Classical',
                    'Family': name.split('-')[0],
                    'Security Level': self._get_classical_security_level(name),
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
                    'Shared Secret Size (bytes)': data['sizes']['shared_secret']
                }
                platform_data['kem'][platform].append(record)
            
            # Process signature data with message sizes
            for name, data in results['pqc']['results']['signatures'].items():
                base_record = {
                    'Platform': platform.upper(),
                    'Algorithm': name,
                    'Type': 'Post-Quantum',
                    'Family': name.split('-')[0],
                    'Security Level': data['algorithm_details']['claimed_nist_level'],
                    # Key Generation metrics
                    'Key Generation (ms)': data['statistics']['key_generation']['mean_ms'],
                    'Key Gen Std (ms)': data['statistics']['key_generation']['std_ms'],
                    # Size metrics
                    'Public Key Size (bytes)': data['sizes']['public_key'],
                    'Secret Key Size (bytes)': data.get('sizes', {}).get('secret_key', 0),
                }
                
                # Add records for each message size
                for msg_size in data['statistics']['signing'].keys():
                    record = base_record.copy()
                    record.update({
                        'Message Size (bytes)': int(msg_size),
                        'Signing (ms)': data['statistics']['signing'][msg_size]['mean_ms'],
                        'Sign Std (ms)': data['statistics']['signing'][msg_size]['std_ms'],
                        'Verification (ms)': data['statistics']['verification'][msg_size]['mean_ms'],
                        'Verify Std (ms)': data['statistics']['verification'][msg_size]['std_ms'],
                        'Signature Size (bytes)': data['sizes'][f'signature_{msg_size}']
                    })
                    platform_data['sig'][platform].append(record)
            
            # Process classical signatures
            for name, data in results['baseline']['results']['signatures'].items():
                base_record = {
                    'Platform': platform.upper(),
                    'Algorithm': name,
                    'Type': 'Classical',
                    'Family': name.split('-')[0],
                    'Security Level': self._get_classical_security_level(name),
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
                        'Signature Size (bytes)': data['sizes'][f'signature_{msg_size}']
                    })
                    platform_data['sig'][platform].append(record)
        
        # Convert to DataFrames
        for key in platform_data:
            for platform in self.platforms:
                if platform_data[key][platform]:
                    platform_data[key][platform] = pd.DataFrame(platform_data[key][platform])
        
        return platform_data
    
    def _get_classical_security_level(self, name: str) -> int:
        """Get NIST security level for classical algorithms"""
        if 'RSA' in name:
            key_size = int(name.split('-')[-1])
            if key_size <= 2048: return 1
            if key_size <= 3072: return 3
            return 5
        if 'ECDSA' in name or 'ECDH' in name:
            key_size = int(name.split('-')[-1])
            if key_size <= 256: return 1
            if key_size <= 384: return 3
            return 5
        return 1

    def analyze_desktop_comparison(self):
        """Compare performance between macOS and Ubuntu"""
        # Get data for desktop platforms
        macos_data = {
            'kem': self.platform_data['kem']['macos'],
            'sig': self.platform_data['sig']['macos']
        }
        ubuntu_data = {
            'kem': self.platform_data['kem']['ubuntu'],
            'sig': self.platform_data['sig']['ubuntu']
        }

        # KEM Performance Ratio Analysis
        kem_metrics = ['Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)']
        
        kem_ratios = []
        for alg in macos_data['kem']['Algorithm'].unique():
            mac_perf = macos_data['kem'][macos_data['kem']['Algorithm'] == alg][kem_metrics]
            ubu_perf = ubuntu_data['kem'][ubuntu_data['kem']['Algorithm'] == alg][kem_metrics]
            
            ratio = (ubu_perf.mean() / mac_perf.mean()).round(2)
            ratio['Algorithm'] = alg
            ratio['Type'] = macos_data['kem'][macos_data['kem']['Algorithm'] == alg]['Type'].iloc[0]
            ratio['Family'] = macos_data['kem'][macos_data['kem']['Algorithm'] == alg]['Family'].iloc[0]
            kem_ratios.append(ratio)
        
        kem_ratio_df = pd.DataFrame(kem_ratios)
        
        # Plot KEM Performance Ratios using bar plots
        plt.figure(figsize=(15, 8))
        plot_data = kem_ratio_df.melt(
            id_vars=['Algorithm', 'Type', 'Family'],
            value_vars=kem_metrics,
            var_name='Operation',
            value_name='Ubuntu/macOS Ratio'
        )
        
        g = sns.barplot(
            data=plot_data,
            x='Family',
            y='Ubuntu/macOS Ratio',
            hue='Operation',
            palette='husl',
            width=0.8
        )
        
        plt.axhline(y=1.0, color='red', linestyle='--', alpha=0.5)
        plt.title('KEM Performance Ratio (Ubuntu/macOS)')
        plt.xticks(rotation=45)
        
        # Add value labels
        for container in g.containers:
            g.bar_label(container, 
                       fmt='%.2f', 
                       label_type='edge',
                       rotation=0,
                       fontsize=8,
                       padding=2)
        
        # Update legend in plot
        plt.legend(title='Operation', 
              bbox_to_anchor=(1.05, 1),
              loc='upper left')
        plt.tight_layout()
        plt.savefig(self.output_dir / 'figures' / 'desktop_kem_ratio.pdf')
        plt.close()

        # Save KEM ratio table
        with open(self.output_dir / 'tables' / 'desktop_kem_ratio.tex', 'w') as f:
            f.write(kem_ratio_df.round(2).to_latex(
                caption='KEM Performance Ratios between Ubuntu and macOS',
                label='tab:desktop_kem_ratio',
                escape=False,
                float_format='%.2f'
            ))

        # Signature Performance Ratio Analysis
        sig_metrics = ['Key Generation (ms)', 'Signing (ms)', 'Verification (ms)']
        
        # Analyze signatures for each message size
        message_sizes = sorted(macos_data['sig']['Message Size (bytes)'].unique())
        
        for msg_size in message_sizes:
            sig_ratios = []
            
            # Filter data for current message size
            mac_sig_data = macos_data['sig'][macos_data['sig']['Message Size (bytes)'] == msg_size]
            ubu_sig_data = ubuntu_data['sig'][ubuntu_data['sig']['Message Size (bytes)'] == msg_size]
            
            for alg in mac_sig_data['Algorithm'].unique():
                mac_perf = mac_sig_data[mac_sig_data['Algorithm'] == alg][sig_metrics]
                ubu_perf = ubu_sig_data[ubu_sig_data['Algorithm'] == alg][sig_metrics]
                
                ratio = (ubu_perf.mean() / mac_perf.mean()).round(2)
                ratio['Algorithm'] = alg
                ratio['Type'] = mac_sig_data[mac_sig_data['Algorithm'] == alg]['Type'].iloc[0]
                ratio['Family'] = mac_sig_data[mac_sig_data['Algorithm'] == alg]['Family'].iloc[0]
                ratio['Message Size'] = msg_size
                sig_ratios.append(ratio)
            
            sig_ratio_df = pd.DataFrame(sig_ratios)
            
            # Plot Signature Performance Ratios for current message size
            plt.figure(figsize=(12, 6))
            plot_data = sig_ratio_df.melt(
                id_vars=['Algorithm', 'Type', 'Family', 'Message Size'],
                value_vars=sig_metrics,
                var_name='Operation',
                value_name='Ubuntu/macOS Ratio'
            )
            
            sns.boxplot(
                data=plot_data,
                x='Family',
                y='Ubuntu/macOS Ratio',
                hue='Operation'
            )
            plt.axhline(y=1.0, color='red', linestyle='--', alpha=0.5)
            plt.title(f'Signature Performance Ratio (Ubuntu/macOS) - Message Size: {msg_size} bytes')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(self.output_dir / 'figures' / f'desktop_sig_ratio_{msg_size}.pdf')
            plt.close()
            
            # Save signature ratio table for current message size
            with open(self.output_dir / 'tables' / f'desktop_sig_ratio_{msg_size}.tex', 'w') as f:
                f.write(sig_ratio_df.round(2).to_latex(
                    caption=f'Signature Performance Ratios between Ubuntu and macOS (Message Size: {msg_size} bytes)',
                    label=f'tab:desktop_sig_ratio_{msg_size}',
                    escape=False,
                    float_format='%.2f'
                ))
        
        # Create aggregate signature performance visualization across message sizes
        all_sig_ratios = []
        for msg_size in message_sizes:
            sig_ratios = []
            mac_sig_data = macos_data['sig'][macos_data['sig']['Message Size (bytes)'] == msg_size]
            ubu_sig_data = ubuntu_data['sig'][ubuntu_data['sig']['Message Size (bytes)'] == msg_size]
            
            for alg in mac_sig_data['Algorithm'].unique():
                mac_perf = mac_sig_data[mac_sig_data['Algorithm'] == alg][sig_metrics]
                ubu_perf = ubu_sig_data[ubu_sig_data['Algorithm'] == alg][sig_metrics]
                
                ratio = (ubu_perf.mean() / mac_perf.mean()).round(2)
                ratio['Algorithm'] = alg
                ratio['Type'] = mac_sig_data[mac_sig_data['Algorithm'] == alg]['Type'].iloc[0]
                ratio['Family'] = mac_sig_data[mac_sig_data['Algorithm'] == alg]['Family'].iloc[0]
                ratio['Message Size'] = msg_size
                all_sig_ratios.append(ratio)
        
        all_sig_ratio_df = pd.DataFrame(all_sig_ratios)
        
        # Plot aggregate signature performance
        plt.figure(figsize=(15, 8))
        plot_data = all_sig_ratio_df.melt(
            id_vars=['Algorithm', 'Type', 'Family', 'Message Size'],
            value_vars=sig_metrics,
            var_name='Operation',
            value_name='Ubuntu/macOS Ratio'
        )

        g = sns.FacetGrid(plot_data, col='Operation', col_wrap=2, height=6)
        g.map_dataframe(
            sns.boxplot,
            x='Message Size',
            y='Ubuntu/macOS Ratio',
            hue='Family',
            palette='deep'  # or any other seaborn palette name
        )

        # Add horizontal line at y=1.0 to each facet
        for ax in g.axes.flat:
            ax.axhline(y=1.0, color='red', linestyle='--', alpha=0.5)

        g.fig.suptitle('Signature Performance Ratios by Message Size and Operation Type')
        plt.tight_layout()
        plt.savefig(self.output_dir / 'figures' / 'desktop_sig_ratio_aggregate.pdf')
        plt.close()

    def analyze_raspberry_performance(self):
        """Analyze performance characteristics on Raspberry Pi"""
        # Get baseline (macOS) data
        macos_data = {
            'kem': self.platform_data['kem']['macos'],
            'sig': self.platform_data['sig']['macos']
        }
        pi_data = {
            'kem': self.platform_data['kem']['raspberry'],
            'sig': self.platform_data['sig']['raspberry']
        }

        # Calculate slowdown factors
        metrics = {
            'kem': ['Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)'],
            'sig': ['Key Generation (ms)', 'Signing (ms)', 'Verification (ms)']
        }

        # KEM Slowdown Analysis
        kem_slowdown = []
        for alg in macos_data['kem']['Algorithm'].unique():
            mac_perf = macos_data['kem'][macos_data['kem']['Algorithm'] == alg][metrics['kem']]
            pi_perf = pi_data['kem'][pi_data['kem']['Algorithm'] == alg][metrics['kem']]
            
            slowdown = (pi_perf.mean() / mac_perf.mean()).round(2)
            slowdown['Algorithm'] = alg
            slowdown['Type'] = macos_data['kem'][macos_data['kem']['Algorithm'] == alg]['Type'].iloc[0]
            slowdown['Family'] = macos_data['kem'][macos_data['kem']['Algorithm'] == alg]['Family'].iloc[0]
            kem_slowdown.append(slowdown)
        
        kem_slowdown_df = pd.DataFrame(kem_slowdown)

        # Plot KEM Slowdown Factors
        plt.figure(figsize=(12, 6))
        plot_data = kem_slowdown_df.melt(
            id_vars=['Algorithm', 'Type', 'Family'],
            value_vars=metrics['kem'],
            var_name='Operation',
            value_name='Slowdown Factor'
        )
        
        sns.boxplot(
            data=plot_data,
            x='Family',
            y='Slowdown Factor',
            hue='Operation'
        )
        plt.yscale('log')
        plt.title('KEM Performance Slowdown on Raspberry Pi')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(self.output_dir / 'figures' / 'pi_kem_slowdown.pdf')
        plt.close()

        # Save KEM slowdown table
        with open(self.output_dir / 'tables' / 'pi_kem_slowdown.tex', 'w') as f:
            f.write(kem_slowdown_df.round(2).to_latex(
                caption='KEM Performance Slowdown Factors on Raspberry Pi',
                label='tab:pi_kem_slowdown',
                escape=False,
                float_format='%.2f'
            ))

    def analyze_signature_performance(self):
        """Analyze signature performance across platforms"""
        # Base metrics for signatures
        sig_metrics = ['Key Generation (ms)', 'Signing (ms)', 'Verification (ms)']
        
        # First compare desktop platforms (macOS vs Ubuntu)
        mac_sig = self.platform_data['sig']['macos']
        ubuntu_sig = self.platform_data['sig']['ubuntu']
        pi_sig = self.platform_data['sig']['raspberry']
        
        # Analyze for each message size
        message_sizes = sorted(mac_sig['Message Size (bytes)'].unique())
        
        desktop_ratios = []
        pi_slowdown = []
        
        for msg_size in message_sizes:
            # Get data for specific message size
            mac_data = mac_sig[mac_sig['Message Size (bytes)'] == msg_size]
            ubuntu_data = ubuntu_sig[ubuntu_sig['Message Size (bytes)'] == msg_size]
            pi_data = pi_sig[pi_sig['Message Size (bytes)'] == msg_size]
            
            # Calculate ratios for each algorithm
            for alg in mac_data['Algorithm'].unique():
                # Desktop comparison
                mac_perf = mac_data[mac_data['Algorithm'] == alg][sig_metrics].mean()
                ubuntu_perf = ubuntu_data[ubuntu_data['Algorithm'] == alg][sig_metrics].mean()
                
                ratio = (ubuntu_perf / mac_perf).round(2)
                ratio['Algorithm'] = alg
                ratio['Message Size'] = msg_size
                ratio['Type'] = mac_data[mac_data['Algorithm'] == alg]['Type'].iloc[0]
                ratio['Family'] = mac_data[mac_data['Algorithm'] == alg]['Family'].iloc[0]
                desktop_ratios.append(ratio)
                
                # Raspberry Pi slowdown
                pi_perf = pi_data[pi_data['Algorithm'] == alg][sig_metrics].mean()
                slowdown = (pi_perf / mac_perf).round(2)
                slowdown['Algorithm'] = alg
                slowdown['Message Size'] = msg_size
                slowdown['Type'] = mac_data[mac_data['Algorithm'] == alg]['Type'].iloc[0]
                slowdown['Family'] = mac_data[mac_data['Algorithm'] == alg]['Family'].iloc[0]
                pi_slowdown.append(slowdown)
        
        desktop_ratio_df = pd.DataFrame(desktop_ratios)
        pi_slowdown_df = pd.DataFrame(pi_slowdown)
        
        # Plot signature performance comparisons
        for msg_size in message_sizes:
            # Desktop comparison plot
            plt.figure(figsize=(12, 6))
            plot_data = desktop_ratio_df[desktop_ratio_df['Message Size'] == msg_size].melt(
                id_vars=['Algorithm', 'Type', 'Family'],
                value_vars=sig_metrics,
                var_name='Operation',
                value_name='Ubuntu/macOS Ratio'
            )
            
            sns.boxplot(
                data=plot_data,
                x='Family',
                y='Ubuntu/macOS Ratio',
                hue='Operation'
            )
            plt.axhline(y=1.0, color='red', linestyle='--', alpha=0.5)
            plt.title(f'Signature Performance Ratio - Message Size: {msg_size} bytes')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.legend(title='Operation Types',
                  bbox_to_anchor=(1.05, 1),
                  loc='upper left')
            plt.savefig(self.output_dir / 'figures' / f'desktop_sig_ratio_{msg_size}.pdf')
            plt.close()
            
            # Raspberry Pi slowdown plot
            plt.figure(figsize=(12, 6))
            plot_data = pi_slowdown_df[pi_slowdown_df['Message Size'] == msg_size].melt(
                id_vars=['Algorithm', 'Type', 'Family'],
                value_vars=sig_metrics,
                var_name='Operation',
                value_name='Slowdown Factor'
            )
            
            sns.boxplot(
                data=plot_data,
                x='Family',
                y='Slowdown Factor',
                hue='Operation'
            )
            plt.yscale('log')
            plt.title(f'Signature Slowdown on Raspberry Pi - Message Size: {msg_size} bytes')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(self.output_dir / 'figures' / f'pi_sig_slowdown_{msg_size}.pdf')
            plt.close()

    def analyze_resource_requirements(self):
        """Analyze resource requirements and provide recommendations"""
        # Use Raspberry Pi data for resource analysis
        pi_kem = self.platform_data['kem']['raspberry']
        pi_sig = self.platform_data['sig']['raspberry']
        
        # KEM Resource Analysis
        kem_resources = []
        for _, row in pi_kem.iterrows():
            resource = {
                'Algorithm': row['Algorithm'],
                'Family': row['Family'],
                'Type': row['Type'],
                'Total Time (ms)': row['Key Generation (ms)'] + row['Encapsulation (ms)'] + row['Decapsulation (ms)'],
                'Memory Overhead (bytes)': row['Public Key Size (bytes)'] + row['Secret Key Size (bytes)'] + row['Ciphertext Size (bytes)'],
                'Security Level': row['Security Level']
            }
            kem_resources.append(resource)
        
        kem_resource_df = pd.DataFrame(kem_resources)
        
        # Plot KEM Resource Requirements
        plt.figure(figsize=(10, 8))
        sns.scatterplot(
            data=kem_resource_df,
            x='Total Time (ms)',
            y='Memory Overhead (bytes)',
            hue='Family',
            style='Security Level',
            size='Security Level',
            sizes=(50, 200)
        )
        
        plt.xscale('log')
        plt.yscale('log')
        plt.title('KEM Resource Requirements on Raspberry Pi')
        
        # Add algorithm labels for notable points
        for idx, row in kem_resource_df.iterrows():
            if row['Security Level'] >= 3:
                plt.annotate(
                    row['Algorithm'].split('-')[0],
                    (row['Total Time (ms)'], row['Memory Overhead (bytes)']),
                    xytext=(5, 5),
                    textcoords='offset points',
                    fontsize=7
                )
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'figures' / 'kem_resource_requirements.pdf')
        plt.close()
        
        # Signature Resource Analysis (for median message size)
        sig_resources = []
        msg_sizes = sorted(pi_sig['Message Size (bytes)'].unique())
        median_size = msg_sizes[len(msg_sizes)//2]
        
        for alg in pi_sig['Algorithm'].unique():
            alg_data = pi_sig[(pi_sig['Algorithm'] == alg) & 
                            (pi_sig['Message Size (bytes)'] == median_size)].iloc[0]
            
            resource = {
                'Algorithm': alg,
                'Family': alg_data['Family'],
                'Type': alg_data['Type'],
                'Total Time (ms)': alg_data['Key Generation (ms)'] + alg_data['Signing (ms)'] + alg_data['Verification (ms)'],
                'Memory Overhead (bytes)': alg_data['Public Key Size (bytes)'] + alg_data['Secret Key Size (bytes)'] + alg_data['Signature Size (bytes)'],
                'Security Level': alg_data['Security Level']
            }
            sig_resources.append(resource)
        
        sig_resource_df = pd.DataFrame(sig_resources)
        
        # Plot Signature Resource Requirements
        plt.figure(figsize=(10, 8))
        sns.scatterplot(
            data=sig_resource_df,
            x='Total Time (ms)',
            y='Memory Overhead (bytes)',
            hue='Family',
            style='Security Level',
            size='Security Level',
            sizes=(50, 200)
        )
        
        plt.xscale('log')
        plt.yscale('log')
        plt.title(f'Signature Resource Requirements on Raspberry Pi (Message Size: {median_size} bytes)')
        
        # Add algorithm labels for notable points
        for idx, row in sig_resource_df.iterrows():
            if row['Security Level'] >= 3:
                plt.annotate(
                    row['Algorithm'].split('-')[0],
                    (row['Total Time (ms)'], row['Memory Overhead (bytes)']),
                    xytext=(5, 5),
                    textcoords='offset points',
                    fontsize=7
                )
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'figures' / 'sig_resource_requirements.pdf')
        plt.close()

        # Generate recommendations table
        self.generate_recommendations(kem_resource_df, sig_resource_df)

    def generate_recommendations(self, kem_df: pd.DataFrame, sig_df: pd.DataFrame):
        """Generate deployment recommendations based on resource requirements"""
        # Define resource constraints for different scenarios
        scenarios = {
            'Very Constrained (IoT Sensors)': {
                'max_time_ms': 100,
                'max_memory_bytes': 10000
            },
            'Moderately Constrained (Raspberry Pi)': {
                'max_time_ms': 1000,
                'max_memory_bytes': 100000
            },
            'Less Constrained (Edge Devices)': {
                'max_time_ms': 5000,
                'max_memory_bytes': 1000000
            }
        }
        
        recommendations = []
        
        # Generate recommendations for each scenario
        for scenario, constraints in scenarios.items():
            # KEM recommendations
            suitable_kems = kem_df[
                (kem_df['Total Time (ms)'] <= constraints['max_time_ms']) &
                (kem_df['Memory Overhead (bytes)'] <= constraints['max_memory_bytes'])
            ]
            
            # Signature recommendations
            suitable_sigs = sig_df[
                (sig_df['Total Time (ms)'] <= constraints['max_time_ms']) &
                (sig_df['Memory Overhead (bytes)'] <= constraints['max_memory_bytes'])
            ]
            
            recommendation = {
                'Scenario': scenario,
                'Recommended KEMs': ', '.join(suitable_kems['Algorithm'].unique()),
                'Recommended Signatures': ', '.join(suitable_sigs['Algorithm'].unique()),
                'Notes': f"Based on time limit {constraints['max_time_ms']}ms and memory limit {constraints['max_memory_bytes']} bytes"
            }
            
            recommendations.append(recommendation)
        
        recommendations_df = pd.DataFrame(recommendations)
        
        # Save recommendations table
        with open(self.output_dir / 'tables' / 'deployment_recommendations.tex', 'w') as f:
            f.write(recommendations_df.to_latex(
                caption='Algorithm Recommendations for Different Deployment Scenarios',
                label='tab:deployment_recommendations',
                escape=False,
                longtable=True
            ))

def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Analyze cross-platform performance of PQC algorithms.'
    )
    parser.add_argument(
        '--results-dir',
        type=Path,
        default=Path('results'),
        help='Base directory containing benchmark results'
    )
    
    args = parser.parse_args()
    
    try:
        analyzer = PlatformComparisonAnalyzer(args.results_dir)
        
        print("Analyzing desktop platform comparison...")
        analyzer.analyze_desktop_comparison()
        
        print("Analyzing Raspberry Pi performance...")
        analyzer.analyze_raspberry_performance()
        
        print("Analyzing signature performance...")
        analyzer.analyze_signature_performance()
        
        print("Analyzing resource requirements...")
        analyzer.analyze_resource_requirements()
        
        print(f"\nAnalysis complete. Results saved in {analyzer.output_dir}")
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        raise

if __name__ == '__main__':
    main()