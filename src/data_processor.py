"""Data Processing Module - Normalizes and prepares forensic data for analysis"""

import pandas as pd
from typing import Dict, List, Any
from rich.console import Console
import re

console = Console()


class DataProcessor:
    """Processes and normalizes forensic data from multiple sources"""
    
    # Common suspicious patterns
    SUSPICIOUS_PATTERNS = {
        'executable_extensions': ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.com'],
        'suspicious_paths': [
            r'temp', r'tmp', r'appdata', r'local.*temp',
            r'programdata', r'windows.*system32', r'syswow64'
        ],
        'suspicious_keywords': [
            'malware', 'trojan', 'virus', 'backdoor', 'keylogger',
            'ransomware', 'rootkit', 'exploit', 'payload', 'shellcode'
        ],
        'suspicious_ports': [4444, 5555, 6666, 6667, 12345, 31337, 8080, 9999],
        'suspicious_ips': [
            r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[01])\.', r'^192\.168\.'
        ]
    }
    
    def __init__(self, dataframes: Dict[str, pd.DataFrame]):
        """
        Initialize data processor
        
        Args:
            dataframes: Dictionary of dataframes from CSV ingestion
        """
        self.dataframes = dataframes
        self.processed_data = {}
        self.anomalies = []
        
    def normalize_column_names(self, df: pd.DataFrame) -> pd.DataFrame:
        """Normalize column names to lowercase with underscores"""
        df.columns = df.columns.str.lower().str.replace(' ', '_').str.replace('-', '_')
        return df
    
    def detect_suspicious_patterns(self, df: pd.DataFrame, source_name: str) -> List[Dict[str, Any]]:
        """
        Detect suspicious patterns in the dataframe
        
        Args:
            df: DataFrame to analyze
            source_name: Name of the data source
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        df_lower = df.copy()
        
        # Convert all string columns to lowercase for pattern matching
        for col in df_lower.select_dtypes(include=['object']).columns:
            df_lower[col] = df_lower[col].astype(str).str.lower()
        
        # Check for suspicious file extensions
        for col in df_lower.select_dtypes(include=['object']).columns:
            for ext in self.SUSPICIOUS_PATTERNS['executable_extensions']:
                matches = df_lower[df_lower[col].str.contains(ext, na=False, regex=False)]
                if not matches.empty:
                    for idx, row in matches.iterrows():
                        anomalies.append({
                            'source': source_name,
                            'type': 'suspicious_extension',
                            'severity': 'medium',
                            'column': col,
                            'value': str(row[col]),
                            'row_index': idx,
                            'description': f"Found suspicious extension {ext} in {col}"
                        })
        
        # Check for suspicious keywords
        for col in df_lower.select_dtypes(include=['object']).columns:
            for keyword in self.SUSPICIOUS_PATTERNS['suspicious_keywords']:
                matches = df_lower[df_lower[col].str.contains(keyword, na=False, regex=False)]
                if not matches.empty:
                    for idx, row in matches.iterrows():
                        anomalies.append({
                            'source': source_name,
                            'type': 'suspicious_keyword',
                            'severity': 'high',
                            'column': col,
                            'value': str(row[col]),
                            'row_index': idx,
                            'description': f"Found suspicious keyword '{keyword}' in {col}"
                        })
        
        # Check for suspicious paths
        for col in df_lower.select_dtypes(include=['object']).columns:
            for pattern in self.SUSPICIOUS_PATTERNS['suspicious_paths']:
                matches = df_lower[df_lower[col].str.contains(pattern, na=False, regex=True)]
                if not matches.empty:
                    for idx, row in matches.iterrows():
                        anomalies.append({
                            'source': source_name,
                            'type': 'suspicious_path',
                            'severity': 'medium',
                            'column': col,
                            'value': str(row[col]),
                            'row_index': idx,
                            'description': f"Found suspicious path pattern in {col}"
                        })
        
        return anomalies
    
    def process_all(self) -> Dict[str, pd.DataFrame]:
        """
        Process all dataframes
        
        Returns:
            Dictionary of processed dataframes
        """
        console.print("[bold]Processing forensic data...[/bold]\n")
        
        for name, df in self.dataframes.items():
            console.print(f"Processing [cyan]{name}[/cyan]...")
            
            # Normalize column names
            df_processed = self.normalize_column_names(df.copy())
            
            # Detect anomalies
            detected_anomalies = self.detect_suspicious_patterns(df_processed, name)
            self.anomalies.extend(detected_anomalies)
            
            # Store processed dataframe
            self.processed_data[name] = df_processed
            
            if detected_anomalies:
                console.print(f"  [yellow]Found {len(detected_anomalies)} pattern-based anomalies[/yellow]")
            else:
                console.print(f"  [green]No obvious pattern-based anomalies[/green]")
        
        console.print(f"\n[bold]Total pattern-based anomalies detected: {len(self.anomalies)}[/bold]\n")
        return self.processed_data
    
    def get_combined_data_summary(self) -> str:
        """Get a summary of all processed data"""
        summary_lines = []
        summary_lines.append("=" * 60)
        summary_lines.append("FORENSIC DATA SUMMARY")
        summary_lines.append("=" * 60)
        
        for name, df in self.processed_data.items():
            summary_lines.append(f"\nSource: {name}")
            summary_lines.append(f"  Rows: {len(df):,}")
            summary_lines.append(f"  Columns: {len(df.columns)}")
            summary_lines.append(f"  Column names: {', '.join(df.columns[:10])}")
            if len(df.columns) > 10:
                summary_lines.append(f"  ... and {len(df.columns) - 10} more")
        
        summary_lines.append("\n" + "=" * 60)
        return "\n".join(summary_lines)
    
    def get_anomalies(self) -> List[Dict[str, Any]]:
        """Get all detected anomalies"""
        return self.anomalies

