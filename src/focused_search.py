"""Focused Search Module - Searches CSVs based on case context and IOCs"""

import pandas as pd
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.table import Table
import re

console = Console()


class FocusedSearcher:
    """Searches forensic data based on IOCs and case context"""
    
    def __init__(self, processed_data: Dict[str, pd.DataFrame], case_info: Dict[str, Any], iocs: List[str]):
        """
        Initialize focused searcher
        
        Args:
            processed_data: Dictionary of processed dataframes
            case_info: Case information dictionary
            iocs: List of IOCs to search for
        """
        self.processed_data = processed_data
        self.case_info = case_info
        self.iocs = iocs
        self.search_results = {}
        self.matches = []
    
    def _normalize_ioc(self, ioc: str) -> str:
        """Normalize IOC for searching"""
        return ioc.lower().strip()
    
    def _is_ip_address(self, value: str) -> bool:
        """Check if value looks like an IP address"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, value))
    
    def _is_hash(self, value: str) -> bool:
        """Check if value looks like a hash"""
        # MD5: 32 hex chars, SHA1: 40 hex chars, SHA256: 64 hex chars
        hash_pattern = r'^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$'
        return bool(re.match(hash_pattern, value.lower()))
    
    def _is_domain(self, value: str) -> bool:
        """Check if value looks like a domain"""
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, value))
    
    def _is_email(self, value: str) -> bool:
        """Check if value looks like an email"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, value))
    
    def search_dataframe(self, df: pd.DataFrame, source_name: str) -> List[Dict[str, Any]]:
        """
        Search a dataframe for IOCs
        
        Args:
            df: DataFrame to search
            source_name: Name of the data source
            
        Returns:
            List of matches
        """
        matches = []
        df_lower = df.copy()
        
        # Convert all string columns to lowercase for searching
        for col in df_lower.select_dtypes(include=['object']).columns:
            df_lower[col] = df_lower[col].astype(str).str.lower()
        
        # Search for each IOC
        for ioc in self.iocs:
            ioc_normalized = self._normalize_ioc(ioc)
            if not ioc_normalized:
                continue
            
            # Search across all columns
            for col in df_lower.columns:
                # Exact match
                exact_matches = df_lower[df_lower[col] == ioc_normalized]
                
                # Partial match (for longer strings that might contain the IOC)
                partial_matches = df_lower[df_lower[col].str.contains(re.escape(ioc_normalized), na=False, regex=True)]
                
                # Combine matches
                all_matches = pd.concat([exact_matches, partial_matches]).drop_duplicates()
                
                if not all_matches.empty:
                    for idx, row in all_matches.iterrows():
                        match_type = "exact" if idx in exact_matches.index else "partial"
                        
                        # Determine IOC type
                        ioc_type = "unknown"
                        if self._is_ip_address(ioc):
                            ioc_type = "ip_address"
                        elif self._is_hash(ioc):
                            ioc_type = "hash"
                        elif self._is_domain(ioc):
                            ioc_type = "domain"
                        elif self._is_email(ioc):
                            ioc_type = "email"
                        elif ioc.endswith(('.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.scr')):
                            ioc_type = "executable"
                        
                        matches.append({
                            'source': source_name,
                            'ioc': ioc,
                            'ioc_type': ioc_type,
                            'match_type': match_type,
                            'column': col,
                            'row_index': idx,
                            'matched_value': str(row[col]),
                            'full_row': row.to_dict()
                        })
        
        return matches
    
    def search_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Search all dataframes for IOCs
        
        Returns:
            Dictionary mapping source names to matches
        """
        console.print("\n[bold cyan]Searching forensic data for IOCs...[/bold cyan]\n")
        console.print(f"Searching for [yellow]{len(self.iocs)} IOC(s)[/yellow] across [yellow]{len(self.processed_data)} data source(s)[/yellow]\n")
        
        all_matches = {}
        
        for source_name, df in self.processed_data.items():
            console.print(f"Searching [cyan]{source_name}[/cyan]...")
            matches = self.search_dataframe(df, source_name)
            
            if matches:
                all_matches[source_name] = matches
                console.print(f"  [red]⚠ Found {len(matches)} match(es)[/red]")
            else:
                console.print(f"  [green]✓ No matches[/green]")
        
        self.matches = []
        for matches_list in all_matches.values():
            self.matches.extend(matches_list)
        
        total_matches = len(self.matches)
        console.print(f"\n[bold]Total matches found: {total_matches}[/bold]\n")
        
        self.search_results = all_matches
        return all_matches
    
    def display_matches_table(self):
        """Display matches in a formatted table"""
        if not self.matches:
            console.print("[green]✓ No IOC matches found[/green]")
            return
        
        table = Table(title="IOC Matches", show_header=True, header_style="bold magenta")
        table.add_column("Source", style="cyan")
        table.add_column("IOC", style="yellow")
        table.add_column("Type", style="white")
        table.add_column("Column", style="white")
        table.add_column("Match", style="green")
        
        for match in self.matches[:50]:  # Show first 50
            table.add_row(
                match['source'],
                match['ioc'][:30] + "..." if len(match['ioc']) > 30 else match['ioc'],
                match['ioc_type'],
                match['column'],
                match['matched_value'][:40] + "..." if len(match['matched_value']) > 40 else match['matched_value']
            )
        
        if len(self.matches) > 50:
            table.add_row("...", f"... and {len(self.matches) - 50} more matches", "", "", "")
        
        console.print("\n")
        console.print(table)
        console.print("\n")
    
    def get_matches_summary(self) -> Dict[str, Any]:
        """Get summary of matches"""
        summary = {
            'total_matches': len(self.matches),
            'matches_by_source': {},
            'matches_by_ioc_type': {},
            'matches_by_ioc': {}
        }
        
        for match in self.matches:
            # By source
            source = match['source']
            summary['matches_by_source'][source] = summary['matches_by_source'].get(source, 0) + 1
            
            # By IOC type
            ioc_type = match['ioc_type']
            summary['matches_by_ioc_type'][ioc_type] = summary['matches_by_ioc_type'].get(ioc_type, 0) + 1
            
            # By IOC
            ioc = match['ioc']
            summary['matches_by_ioc'][ioc] = summary['matches_by_ioc'].get(ioc, 0) + 1
        
        return summary

