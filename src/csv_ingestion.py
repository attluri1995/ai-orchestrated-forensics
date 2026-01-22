"""File Ingestion Module - Handles loading and parsing CSV, XLSX, and TXT files from forensic tools"""

import pandas as pd
import os
from pathlib import Path
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import track

console = Console()


class FileIngester:
    """Ingests and loads CSV, XLSX, and TXT files from forensic tools"""
    
    def __init__(self, data_directory: str):
        """
        Initialize file ingester
        
        Args:
            data_directory: Path to directory containing forensic data files
        """
        self.data_directory = Path(data_directory)
        self.dataframes: Dict[str, pd.DataFrame] = {}
        self.file_paths: Dict[str, Path] = {}  # Track original file paths
        
    def discover_files(self) -> List[Path]:
        """Discover all CSV, XLSX, and TXT files recursively in the directory"""
        files = []
        
        # Recursively find all CSV, XLSX, and TXT files
        csv_files = list(self.data_directory.rglob("*.csv"))
        xlsx_files = list(self.data_directory.rglob("*.xlsx"))
        txt_files = list(self.data_directory.rglob("*.txt"))
        
        files.extend(csv_files)
        files.extend(xlsx_files)
        files.extend(txt_files)
        
        console.print(f"[green]Found {len(csv_files)} CSV, {len(xlsx_files)} XLSX, and {len(txt_files)} TXT file(s)[/green]")
        return files
    
    def load_file(self, file_path: Path) -> Optional[pd.DataFrame]:
        """
        Load a single file (CSV, XLSX, or TXT)
        
        Args:
            file_path: Path to file
            
        Returns:
            DataFrame or None if loading fails
        """
        try:
            file_ext = file_path.suffix.lower()
            
            # Load CSV files
            if file_ext == '.csv':
                encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
                df = None
                
                for encoding in encodings:
                    try:
                        df = pd.read_csv(file_path, encoding=encoding, low_memory=False)
                        break
                    except UnicodeDecodeError:
                        continue
                
                if df is None:
                    console.print(f"[red]✗[/red] Failed to load {file_path.name}")
                    return None
                    
            # Load XLSX files
            elif file_ext == '.xlsx':
                try:
                    df = pd.read_excel(file_path, engine='openpyxl')
                except Exception as e:
                    console.print(f"[red]✗[/red] Error loading {file_path.name}: {str(e)}")
                    return None
                    
            # Load TXT files (try to parse as CSV first, then as delimited)
            elif file_ext == '.txt':
                encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
                df = None
                
                # Try common delimiters
                delimiters = [',', '\t', '|', ';']
                
                for encoding in encodings:
                    for delimiter in delimiters:
                        try:
                            df = pd.read_csv(file_path, encoding=encoding, sep=delimiter, low_memory=False)
                            # If we got a reasonable number of columns, use this
                            if len(df.columns) > 1:
                                break
                        except:
                            continue
                    if df is not None and len(df.columns) > 1:
                        break
                
                if df is None or len(df.columns) <= 1:
                    # Try reading as fixed-width or single column
                    try:
                        for encoding in encodings:
                            df = pd.read_csv(file_path, encoding=encoding, header=None, low_memory=False)
                            if len(df) > 0:
                                break
                    except:
                        pass
                
                if df is None or len(df) == 0:
                    console.print(f"[yellow]⚠[/yellow] Could not parse {file_path.name} as structured data")
                    return None
            else:
                console.print(f"[yellow]⚠[/yellow] Unsupported file type: {file_ext}")
                return None
            
            if df is not None and len(df) > 0:
                console.print(f"[green]✓[/green] Loaded {file_path.name} ({len(df)} rows, {len(df.columns)} cols)")
                return df
            else:
                console.print(f"[red]✗[/red] Empty file: {file_path.name}")
                return None
                
        except Exception as e:
            console.print(f"[red]✗[/red] Error loading {file_path.name}: {str(e)}")
            return None
    
    def ingest_all(self) -> Dict[str, pd.DataFrame]:
        """
        Load all CSV, XLSX, and TXT files recursively from the directory
        
        Returns:
            Dictionary mapping file names to DataFrames
        """
        files = self.discover_files()
        
        if not files:
            console.print("[yellow]No files found in directory[/yellow]")
            return {}
        
        console.print(f"\n[bold]Ingesting {len(files)} file(s)...[/bold]\n")
        
        for file_path in track(files, description="Loading files"):
            df = self.load_file(file_path)
            if df is not None:
                # Use relative path as key to handle duplicates
                rel_path = file_path.relative_to(self.data_directory)
                key = str(rel_path).replace('/', '_').replace('\\', '_')
                self.dataframes[key] = df
                self.file_paths[key] = file_path
        
        console.print(f"\n[green]Successfully loaded {len(self.dataframes)} file(s)[/green]\n")
        return self.dataframes
    
    def get_file_path(self, key: str) -> Optional[Path]:
        """Get original file path for a dataframe key"""
        return self.file_paths.get(key)
    
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

