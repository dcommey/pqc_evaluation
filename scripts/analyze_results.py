#!/usr/bin/env python3
"""
Publication-quality analysis of post-quantum cryptography benchmarks.
Generates figures and tables for the results section.
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

class PublicationAnalyzer:
    """Generates publication-quality figures and tables for results section."""
    
    def __init__(self, results_base: Path):
        self.results_base = results_base
        self.output_dir = results_base / 'publication'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / 'figures').mkdir(exist_ok=True)
        (self.output_dir / 'tables').mkdir(exist_ok=True)
        
        # Load all platform results
        self.platforms = ['macos', 'ubuntu', 'raspberry']
        self.results = self.load_all_results()
        
        # Process data for all analyses
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

    def generate_platform_comparison(self):
        """Generate cross-platform comparison plots and tables"""
        self._generate_kem_platform_comparison()
        self._generate_sig_platform_comparison()
    
    def _generate_kem_platform_comparison(self):
        """Generate KEM cross-platform comparison plots and tables"""
        # Combine data from all platforms
        kem_data = pd.concat([
            df for platform, df in self.platform_data['kem'].items()
            if df is not None
        ]).reset_index(drop=True)
        
        # Figure 1: KEM Performance Across Platforms - Bar Plot
        plt.figure(figsize=(15, 8))
        metrics = ['Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)']
        
        plot_data = kem_data.melt(
            id_vars=['Platform', 'Algorithm', 'Type'],
            value_vars=metrics,
            var_name='Operation',
            value_name='Time (ms)'
        )
        
        g = sns.barplot(
            data=plot_data,
            x='Platform',
            y='Time (ms)',
            hue='Operation',
            palette='husl',
            width=0.8
        )
        
        plt.yscale('log')
        plt.title('KEM Performance Across Platforms')
        
        # Add value labels
        for container in g.containers:
            g.bar_label(container, 
                       fmt='%.2f', 
                       label_type='edge',
                       rotation=0,
                       fontsize=8,
                       padding=2)
        
        plt.legend(title='Operation',
                  bbox_to_anchor=(1.05, 1),
                  loc='upper left')
        plt.tight_layout()
        plt.savefig(self.output_dir / 'figures' / 'kem_platform_perf.pdf')
        plt.close()
        
        # Table 1: KEM Performance Statistics
        stats_table = []
        for platform in self.platforms:
            if platform not in self.platform_data['kem']:
                continue
                
            platform_stats = self.platform_data['kem'][platform].groupby('Type')[metrics].agg([
                ('mean', 'mean'),
                ('std', 'std')
            ]).round(2)
            
            platform_stats.columns = [
                f"{col[0]} {col[1]}" for col in platform_stats.columns
            ]
            platform_stats['Platform'] = platform.upper()
            stats_table.append(platform_stats.reset_index())
        
        stats_df = pd.concat(stats_table)
        
        # Save LaTeX table
        with open(self.output_dir / 'tables' / 'kem_platform_stats.tex', 'w') as f:
            f.write(stats_df.to_latex(
                index=False,
                caption='KEM Performance Statistics Across Platforms (times in ms)',
                label='tab:kem_platform_stats',
                escape=False,
                float_format='%.2f'
            ))

    def _generate_sig_platform_comparison(self):
        """Generate signature cross-platform comparison plots and tables"""
        # Combine data from all platforms
        sig_data = pd.concat([
            df for platform, df in self.platform_data['sig'].items()
            if df is not None
        ]).reset_index(drop=True)
        
        # Figure 2: Signature Performance Across Platforms
        metrics = ['Key Generation (ms)', 'Signing (ms)', 'Verification (ms)']
        
        plot_data = sig_data.melt(
            id_vars=['Platform', 'Algorithm', 'Type', 'Security Level', 'Message Size (bytes)'],
            value_vars=metrics,
            var_name='Operation',
            value_name='Time (ms)'
        )
        
        # Create line plots for signature performance
        message_sizes = sorted(plot_data['Message Size (bytes)'].unique())
        for msg_size in message_sizes:
            plt.figure(figsize=(15, 8))
            msg_data = plot_data[plot_data['Message Size (bytes)'] == msg_size]
            
            # Plot each platform's data
            for platform in self.platforms:
                platform_data = msg_data[msg_data['Platform'] == platform.upper()]
                for operation in metrics:
                    op_data = platform_data[platform_data['Operation'] == operation]
                    sns.lineplot(
                        data=op_data,
                        x='Algorithm',
                        y='Time (ms)',
                        marker='o',
                        linewidth=2,
                        label=f'{platform.upper()} - {operation}'
                    )
            
            plt.yscale('log')
            plt.title(f'Signature Performance Across Platforms (Message Size: {msg_size} bytes)')
            plt.xticks(rotation=45, ha='right')
            plt.ylabel('Time (ms)')
            plt.legend(title='Platform-Operation',
                      bbox_to_anchor=(1.05, 1),
                      loc='upper left')
            plt.grid(True, alpha=0.2)
            plt.tight_layout()
            plt.savefig(self.output_dir / 'figures' / f'sig_platform_perf_{msg_size}.pdf')
            plt.close()
        
        # Table 2: Signature Performance Statistics for each message size
        for msg_size in message_sizes:
            stats_table = []
            for platform in self.platforms:
                if platform not in self.platform_data['sig']:
                    continue
                
                platform_data = self.platform_data['sig'][platform]
                platform_data = platform_data[platform_data['Message Size (bytes)'] == msg_size]
                
                platform_stats = platform_data.groupby('Type')[metrics].agg([
                    ('mean', 'mean'),
                    ('std', 'std')
                ]).round(2)
                
                platform_stats.columns = [
                    f"{col[0]} {col[1]}" for col in platform_stats.columns
                ]
                platform_stats['Platform'] = platform.upper()
                stats_table.append(platform_stats.reset_index())
            
            stats_df = pd.concat(stats_table)
            
            # Save LaTeX table
            with open(self.output_dir / 'tables' / f'sig_platform_stats_{msg_size}.tex', 'w') as f:
                f.write(stats_df.to_latex(
                    index=False,
                    caption=f'Signature Performance Statistics (Message Size: {msg_size} bytes)',
                    label=f'tab:sig_platform_stats_{msg_size}',
                    escape=False,
                    float_format='%.2f'
                ))

    def generate_communication_analysis(self):
        """Generate communication overhead analysis plots and tables"""
        # KEM Communication Analysis
        kem_data = pd.concat([
            df for platform, df in self.platform_data['kem'].items()
            if df is not None
        ]).reset_index(drop=True)
        
        # Figure 3: KEM Communication Overhead
        plt.figure(figsize=(10, 8))
        g = sns.scatterplot(
            data=kem_data,
            x='Public Key Size (bytes)',
            y='Ciphertext Size (bytes)',
            hue='Type',
            style='Security Level',
            size='Security Level',
            sizes=(50, 200)
        )
        
        plt.xscale('log')
        plt.yscale('log')
        
        # Add algorithm labels for notable points
        for idx, row in kem_data.iterrows():
            if row['Type'] == 'Post-Quantum' and row['Security Level'] >= 3:
                plt.annotate(
                    row['Algorithm'].split('-')[0],
                    (row['Public Key Size (bytes)'], row['Ciphertext Size (bytes)']),
                    xytext=(5, 5),
                    textcoords='offset points',
                    fontsize=7
                )
        
        plt.title('KEM Communication Overhead')
        plt.grid(True, which="both", ls="-", alpha=0.2)
        plt.tight_layout()
        plt.savefig(self.output_dir / 'figures' / 'kem_comm_overhead.pdf')
        plt.close()
        
        # Table 3: KEM Communication Costs
        size_metrics = ['Public Key Size (bytes)', 'Secret Key Size (bytes)', 
                        'Ciphertext Size (bytes)', 'Shared Secret Size (bytes)']
        
        comm_stats = kem_data.groupby(['Family', 'Type'])[size_metrics].agg([
            'mean', 'min', 'max'
        ]).round(0)
        
        with open(self.output_dir / 'tables' / 'kem_comm_costs.tex', 'w') as f:
            f.write(comm_stats.to_latex(
                caption='KEM Communication Costs by Algorithm Family (bytes)',
                label='tab:kem_comm_costs',
                escape=False,
                float_format='%.0f'
            ))
        
        # Signature Communication Analysis
        sig_data = pd.concat([
            df for platform, df in self.platform_data['sig'].items()
            if df is not None
        ]).reset_index(drop=True)
        
        # Average signature size across message sizes
        sig_size_avg = sig_data.groupby(
            ['Algorithm', 'Type', 'Security Level', 'Family', 'Public Key Size (bytes)']
        )['Signature Size (bytes)'].mean().reset_index()
        
        # Figure 4: Signature Communication Overhead
        plt.figure(figsize=(10, 8))
        g = sns.scatterplot(
            data=sig_size_avg,
            x='Public Key Size (bytes)',
            y='Signature Size (bytes)',
            hue='Type',
            style='Security Level',
            size='Security Level',
            sizes=(50, 200)
        )
        
        plt.xscale('log')
        plt.yscale('log')
        
        # Add algorithm labels for notable points
        for idx, row in sig_size_avg.iterrows():
            if row['Type'] == 'Post-Quantum' and row['Security Level'] >= 3:
                plt.annotate(
                    row['Algorithm'].split('-')[0],
                    (row['Public Key Size (bytes)'], row['Signature Size (bytes)']),
                    xytext=(5, 5),
                    textcoords='offset points',
                    fontsize=7
                )
        
        plt.title('Signature Communication Overhead')
        plt.grid(True, which="both", ls="-", alpha=0.2)
        plt.tight_layout()
        plt.savefig(self.output_dir / 'figures' / 'sig_comm_overhead.pdf')
        plt.close()

    def generate_security_analysis(self):
        """Generate security level analysis plots and tables"""
        # Use macOS data as reference platform
        kem_data = self.platform_data['kem']['macos']
        sig_data = self.platform_data['sig']['macos']
        
        # Figure 5: KEM Performance vs Security Level
        kem_perf_metrics = ['Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)']
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 15))
        fig.suptitle('KEM Performance and Size vs NIST Security Level')
        
        # Performance plots
        plot_data = kem_data.melt(
            id_vars=['Security Level', 'Type', 'Algorithm'],
            value_vars=kem_perf_metrics,
            var_name='Operation',
            value_name='Time (ms)'
        )
        
        # Top left: Performance boxplot
        sns.boxplot(
            data=plot_data,
            x='Security Level',
            y='Time (ms)',
            hue='Operation',
            ax=axes[0,0]
        )
        axes[0,0].set_yscale('log')
        axes[0,0].set_title('Operation Times')
        
        # Top right: Size metrics
        kem_size_metrics = ['Public Key Size (bytes)', 'Ciphertext Size (bytes)']
        size_data = kem_data.melt(
            id_vars=['Security Level', 'Type'],
            value_vars=kem_size_metrics,
            var_name='Metric',
            value_name='Size (bytes)'
        )
        
        sns.boxplot(
            data=size_data,
            x='Security Level',
            y='Size (bytes)',
            hue='Metric',
            ax=axes[0,1]
        )
        axes[0,1].set_yscale('log')
        axes[0,1].set_title('Communication Overhead')
        
        # Bottom plots: Classical vs Post-Quantum
        for idx, type_ in enumerate(['Classical', 'Post-Quantum']):
            type_data = plot_data[plot_data['Type'] == type_]
            sns.boxplot(
                data=type_data,
                x='Security Level',
                y='Time (ms)',
                hue='Operation',
                ax=axes[1,idx]
            )
            axes[1,idx].set_yscale('log')
            axes[1,idx].set_title(f'{type_} Algorithms')
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'figures' / 'kem_security_analysis.pdf')
        plt.close()
        
        # Figure 6: Signature Performance vs Security Level
        sig_perf_metrics = ['Key Generation (ms)', 'Signing (ms)', 'Verification (ms)']
        
        # Create plots for each message size
        message_sizes = sorted(sig_data['Message Size (bytes)'].unique())
        for msg_size in message_sizes:
            msg_data = sig_data[sig_data['Message Size (bytes)'] == msg_size]
            
            fig, axes = plt.subplots(2, 2, figsize=(15, 15))
            fig.suptitle(f'Signature Performance and Size vs NIST Security Level (Message Size: {msg_size} bytes)')
            
            # Performance plots
            plot_data = msg_data.melt(
                id_vars=['Security Level', 'Type', 'Algorithm'],
                value_vars=sig_perf_metrics,
                var_name='Operation',
                value_name='Time (ms)'
            )
            
            # Top left: Performance boxplot
            sns.boxplot(
                data=plot_data,
                x='Security Level',
                y='Time (ms)',
                hue='Operation',
                ax=axes[0,0]
            )
            axes[0,0].set_yscale('log')
            axes[0,0].set_title('Operation Times')
            
            # Top right: Size metrics
            sig_size_metrics = ['Public Key Size (bytes)']
            size_data = pd.concat([
                msg_data.melt(
                    id_vars=['Security Level', 'Type'],
                    value_vars=sig_size_metrics,
                    var_name='Metric',
                    value_name='Size (bytes)'
                ),
                msg_data.assign(
                    Metric='Signature Size (bytes)',
                    Size=msg_data['Signature Size (bytes)']
                )[['Security Level', 'Type', 'Metric', 'Size']]
            ])
            
            sns.boxplot(
                data=size_data,
                x='Security Level',
                y='Size (bytes)',
                hue='Metric',
                ax=axes[0,1]
            )
            axes[0,1].set_yscale('log')
            axes[0,1].set_title('Communication Overhead')
            
            # Bottom plots: Classical vs Post-Quantum
            for idx, type_ in enumerate(['Classical', 'Post-Quantum']):
                type_data = plot_data[plot_data['Type'] == type_]
                sns.boxplot(
                    data=type_data,
                    x='Security Level',
                    y='Time (ms)',
                    hue='Operation',
                    ax=axes[1,idx]
                )
                axes[1,idx].set_yscale('log')
                axes[1,idx].set_title(f'{type_} Algorithms')
            
            plt.tight_layout()
            plt.savefig(self.output_dir / 'figures' / f'sig_security_analysis_{msg_size}.pdf')
            plt.close()

        # Table: Security Level Impact
        security_impact = pd.DataFrame()
        
        # Process KEM data
        for level in sorted(kem_data['Security Level'].unique()):
            level_data = kem_data[kem_data['Security Level'] == level]
            for type_ in ['Classical', 'Post-Quantum']:
                type_data = level_data[level_data['Type'] == type_]
                if not type_data.empty:
                    # Performance metrics
                    for metric in kem_perf_metrics:
                        security_impact.loc[f'KEM Level {level}', f'{type_} {metric}'] = \
                            type_data[metric].mean()
                    # Size metrics
                    for metric in kem_size_metrics:
                        security_impact.loc[f'KEM Level {level}', f'{type_} {metric}'] = \
                            type_data[metric].mean()
        
        # Process signature data
        # First group by level and type to get average metrics
        sig_stats = sig_data.groupby(['Security Level', 'Type']).agg({
            'Key Generation (ms)': 'mean',
            'Signing (ms)': 'mean',
            'Verification (ms)': 'mean',
            'Public Key Size (bytes)': 'mean',
            'Signature Size (bytes)': 'mean'
        }).reset_index()
        
        for level in sorted(sig_stats['Security Level'].unique()):
            level_data = sig_stats[sig_stats['Security Level'] == level]
            for type_ in ['Classical', 'Post-Quantum']:
                type_data = level_data[level_data['Type'] == type_]
                if not type_data.empty:
                    # Add all metrics to the security impact table
                    for metric in sig_perf_metrics + ['Public Key Size (bytes)', 'Signature Size (bytes)']:
                        security_impact.loc[f'Signature Level {level}', f'{type_} {metric}'] = \
                            type_data[metric].iloc[0]
        
        # Save table
        with open(self.output_dir / 'tables' / 'security_impact.tex', 'w') as f:
            f.write(security_impact.round(2).to_latex(
                caption='Impact of Security Level on Performance and Size',
                label='tab:security_impact',
                escape=False,
                float_format='%.2f'
            ))

    def generate_family_analysis(self):
        """Generate algorithm family analysis plots and tables"""
        # Use macOS data as reference platform
        kem_data = self.platform_data['kem']['macos']
        sig_data = self.platform_data['sig']['macos']
        
        # KEM Family Analysis
        metrics = ['Key Generation (ms)', 'Encapsulation (ms)', 'Decapsulation (ms)']
        size_metrics = ['Public Key Size (bytes)', 'Ciphertext Size (bytes)']
        
        # Figure 7: KEM Family Performance
        fig, axes = plt.subplots(2, 1, figsize=(15, 12))
        fig.suptitle('KEM Family Performance Comparison')
        
        # Performance plot
        perf_data = kem_data.melt(
            id_vars=['Family', 'Type', 'Algorithm', 'Security Level'],
            value_vars=metrics,
            var_name='Operation',
            value_name='Time (ms)'
        )
        
        sns.boxplot(
            data=perf_data,
            x='Family',
            y='Time (ms)',
            hue='Operation',
            ax=axes[0]
        )
        axes[0].set_yscale('log')
        axes[0].set_title('Performance by Family')
        axes[0].tick_params(axis='x', rotation=45)
        
        # Communication overhead plot
        size_data = kem_data.melt(
            id_vars=['Family', 'Type', 'Security Level'],
            value_vars=size_metrics,
            var_name='Metric',
            value_name='Size (bytes)'
        )
        
        sns.boxplot(
            data=size_data,
            x='Family',
            y='Size (bytes)',
            hue='Metric',
            ax=axes[1]
        )
        axes[1].set_yscale('log')
        axes[1].set_title('Communication Overhead by Family')
        axes[1].tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'figures' / 'kem_family_analysis.pdf')
        plt.close()
        
        # KEM Family Statistics Table
        family_stats = []
        
        for family in kem_data['Family'].unique():
            family_data = kem_data[kem_data['Family'] == family]
            
            # Performance statistics
            perf_stats = family_data[metrics].agg(['mean', 'std']).round(2)
            perf_stats.columns = [f"{col[0]} {col[1]}" for col in perf_stats.columns]
            
            # Size statistics
            size_stats = family_data[size_metrics].agg(['mean', 'min', 'max']).round(0)
            size_stats.columns = [f"{col[0]} {col[1]}" for col in size_stats.columns]
            
            # Combine stats
            stats = pd.concat([perf_stats, size_stats])
            stats['Family'] = family
            family_stats.append(stats)
        
        family_stats_df = pd.concat(family_stats)
        
        with open(self.output_dir / 'tables' / 'kem_family_stats.tex', 'w') as f:
            f.write(family_stats_df.to_latex(
                caption='KEM Family Performance Statistics',
                label='tab:kem_family_stats',
                escape=False
            ))
        
        # Signature Family Analysis
        sig_metrics = ['Key Generation (ms)', 'Signing (ms)', 'Verification (ms)']
        sig_size_metrics = ['Public Key Size (bytes)', 'Signature Size (bytes)']
        
        # Figure 8: Signature Family Performance
        message_sizes = sorted(sig_data['Message Size (bytes)'].unique())
        
        for msg_size in message_sizes:
            msg_data = sig_data[sig_data['Message Size (bytes)'] == msg_size]
            
            fig, axes = plt.subplots(2, 1, figsize=(15, 12))
            fig.suptitle(f'Signature Family Performance Comparison (Message Size: {msg_size} bytes)')
            
            # Performance plot
            perf_data = msg_data.melt(
                id_vars=['Family', 'Type', 'Algorithm', 'Security Level'],
                value_vars=sig_metrics,
                var_name='Operation',
                value_name='Time (ms)'
            )
            
            sns.boxplot(
                data=perf_data,
                x='Family',
                y='Time (ms)',
                hue='Operation',
                ax=axes[0]
            )
            axes[0].set_yscale('log')
            axes[0].set_title('Performance by Family')
            axes[0].tick_params(axis='x', rotation=45)
            
            # Communication overhead plot
            size_data = msg_data.melt(
                id_vars=['Family', 'Type', 'Security Level'],
                value_vars=sig_size_metrics,
                var_name='Metric',
                value_name='Size (bytes)'
            )
            
            sns.boxplot(
                data=size_data,
                x='Family',
                y='Size (bytes)',
                hue='Metric',
                ax=axes[1]
            )
            axes[1].set_yscale('log')
            axes[1].set_title('Communication Overhead by Family')
            axes[1].tick_params(axis='x', rotation=45)
            
            plt.tight_layout()
            plt.savefig(self.output_dir / 'figures' / f'sig_family_analysis_{msg_size}.pdf')
            plt.close()

    def generate_message_size_analysis(self):
        """Generate message size impact analysis plots and tables"""
        # Use macOS data as reference platform
        sig_data = self.platform_data['sig']['macos']
        
        # Figure 9: Performance vs Message Size
        metrics = ['Signing (ms)', 'Verification (ms)']
        
        # Create plots for each family
        for family in sig_data['Family'].unique():
            family_data = sig_data[sig_data['Family'] == family]
            
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
            fig.suptitle(f'Message Size Impact: {family} Family')
            
            # Performance plot
            for metric in metrics:
                sns.lineplot(
                    data=family_data,
                    x='Message Size (bytes)',
                    y=metric,
                    hue='Algorithm',
                    style='Type',
                    markers=True,
                    ax=ax1
                )
            
            ax1.set_xscale('log')
            ax1.set_yscale('log')
            ax1.set_title('Performance Scaling')
            ax1.set_xlabel('Message Size (bytes)')
            ax1.set_ylabel('Time (ms)')
            
            # Signature size plot
            sns.lineplot(
                data=family_data,
                x='Message Size (bytes)',
                y='Signature Size (bytes)',
                hue='Algorithm',
                style='Type',
                markers=True,
                ax=ax2
            )
            
            ax2.set_xscale('log')
            ax2.set_yscale('log')
            ax2.set_title('Signature Size Scaling')
            ax2.set_xlabel('Message Size (bytes)')
            ax2.set_ylabel('Signature Size (bytes)')
            
            plt.tight_layout()
            plt.savefig(self.output_dir / 'figures' / f'msg_size_impact_{family.lower()}.pdf')
            plt.close()
        
        # Table: Message Size Scaling Behavior
        scaling_stats = []
        
        for family in sig_data['Family'].unique():
            family_data = sig_data[sig_data['Family'] == family]
            
            for alg in family_data['Algorithm'].unique():
                alg_data = family_data[family_data['Algorithm'] == alg]
                
                # Calculate scaling factors
                base_size = alg_data['Message Size (bytes)'].min()
                base_sign_time = alg_data[alg_data['Message Size (bytes)'] == base_size]['Signing (ms)'].mean()
                base_verify_time = alg_data[alg_data['Message Size (bytes)'] == base_size]['Verification (ms)'].mean()
                base_sig_size = alg_data[alg_data['Message Size (bytes)'] == base_size]['Signature Size (bytes)'].mean()
                
                scaling = {
                    'Family': family,
                    'Algorithm': alg,
                    'Type': alg_data['Type'].iloc[0],
                    'Base Message Size': base_size,
                    'Base Signing Time': base_sign_time,
                    'Base Verification Time': base_verify_time,
                    'Base Signature Size': base_sig_size
                }
                
                # Calculate scaling for each larger message size
                for size in sorted(alg_data['Message Size (bytes)'].unique())[1:]:
                    size_data = alg_data[alg_data['Message Size (bytes)'] == size]
                    
                    scaling[f'Signing Scale {size}'] = \
                        size_data['Signing (ms)'].mean() / base_sign_time
                    scaling[f'Verify Scale {size}'] = \
                        size_data['Verification (ms)'].mean() / base_verify_time
                    scaling[f'Size Scale {size}'] = \
                        size_data['Signature Size (bytes)'].mean() / base_sig_size
                
                scaling_stats.append(scaling)
        
        scaling_df = pd.DataFrame(scaling_stats)
        
        # Save scaling behavior table
        with open(self.output_dir / 'tables' / 'msg_size_scaling.tex', 'w') as f:
            f.write(scaling_df.round(3).to_latex(
                caption='Performance and Size Scaling with Message Size',
                label='tab:msg_size_scaling',
                escape=False,
                index=False
            ))

def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate publication-quality analysis of PQC benchmarks.'
    )
    parser.add_argument(
        '--results-dir',
        type=Path,
        default=Path('results'),
        help='Base directory containing benchmark results'
    )
    
    args = parser.parse_args()
    
    try:
        analyzer = PublicationAnalyzer(args.results_dir)
        
        print("Generating platform comparison plots and tables...")
        analyzer.generate_platform_comparison()
        
        print("Generating communication overhead analysis...")
        analyzer.generate_communication_analysis()
        
        print("Generating security level analysis...")
        analyzer.generate_security_analysis()
        
        print("Generating algorithm family analysis...")
        analyzer.generate_family_analysis()
        
        print("Generating message size impact analysis...")
        analyzer.generate_message_size_analysis()
        
        print(f"\nAnalysis complete. Results saved in {analyzer.output_dir}")
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        raise

if __name__ == '__main__':
    main()