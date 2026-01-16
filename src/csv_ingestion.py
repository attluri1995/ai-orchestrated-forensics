"""CSV Ingestion Module - Handles loading and parsing CSV files from forensic tools"""

import pandas as pd
import os
from pathlib import Path
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import track

console = Console()


class CSVIngester:
    """Ingests and loads CSV files from forensic tools"""
    
    def __init__(self, csv_directory: str):
        """
        Initialize CSV ingester
        
        Args:
            csv_directory: Path to directory containing CSV files
        """
        self.csv_directory = Path(csv_directory)
        self.dataframes: Dict[str, pd.DataFrame] = {}
        
    def discover_csv_files(self) -> List[Path]:
        """Discover all CSV files in the directory"""
        csv_files = list(self.csv_directory.glob("*.csv"))
        console.print(f"[green]Found {len(csv_files)} CSV file(s)[/green]")
        return csv_files
    
    def load_csv(self, file_path: Path) -> Optional[pd.DataFrame]:
        """
        Load a single CSV file
        
        Args:
            file_path: Path to CSV file
            
        Returns:
            DataFrame or None if loading fails
        """
        try:
            # Try different encodings
            encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
            df = None
            
            for encoding in encodings:
                try:
                    df = pd.read_csv(file_path, encoding=encoding, low_memory=False)
                    console.print(f"[green]✓[/green] Loaded {file_path.name} ({len(df)} rows)")
                    break
                except UnicodeDecodeError:
                    continue
            
            if df is None:
                console.print(f"[red]✗[/red] Failed to load {file_path.name}")
                return None
                
            return df
            
        except Exception as e:
            console.print(f"[red]✗[/red] Error loading {file_path.name}: {str(e)}")
            return None
    
    def ingest_all(self) -> Dict[str, pd.DataFrame]:
        """
        Load all CSV files from the directory
        
        Returns:
            Dictionary mapping file names to DataFrames
        """
        csv_files = self.discover_csv_files()
        
        if not csv_files:
            console.print("[yellow]No CSV files found in directory[/yellow]")
            return {}
        
        console.print(f"\n[bold]Ingesting {len(csv_files)} CSV file(s)...[/bold]\n")
        
        for csv_file in track(csv_files, description="Loading CSVs"):
            df = self.load_csv(csv_file)
            if df is not None:
                # Store with filename as key
                self.dataframes[csv_file.stem] = df
        
        console.print(f"\n[green]Successfully loaded {len(self.dataframes)} CSV file(s)[/green]\n")
        return self.dataframes
    
    def get_dataframe_summary(self) -> Dict[str, Dict]:
        """Get summary statistics for all loaded dataframes"""
        summary = {}
        for name, df in self.dataframes.items():
            summary[name] = {
                'rows': len(df),
                'columns': len(df.columns),
                'column_names': list(df.columns),
                'memory_usage_mb': df.memory_usage(deep=True).sum() / 1024**2
            }
        return summary

