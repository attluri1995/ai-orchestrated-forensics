"""Timeline Generator Module - Creates CSV timeline of identified malicious activities"""

import pandas as pd
from typing import List, Dict, Any, Optional
from pathlib import Path
from rich.console import Console
from datetime import datetime
import re

console = Console()


class TimelineGenerator:
    """Generates CSV timeline of forensic findings"""
    
    def __init__(self, analyst_name: str):
        """
        Initialize timeline generator
        
        Args:
            analyst_name: Name of the analyst performing the analysis
        """
        self.analyst_name = analyst_name
        self.timeline_entries = []
    
    def _extract_timestamp(self, value: Any, df: pd.DataFrame, row_idx: int) -> Optional[str]:
        """
        Extract timestamp from various formats
        
        Args:
            value: Value that might contain a timestamp
            df: DataFrame containing the row
            row_idx: Row index
            
        Returns:
            Formatted timestamp string (yyyy-mm-dd hh:mm:ss) or None
        """
        if pd.isna(value) or value == '':
            return None
        
        value_str = str(value)
        
        # Common timestamp patterns
        patterns = [
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',  # yyyy-mm-dd hh:mm:ss
            r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',  # mm/dd/yyyy hh:mm:ss
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',    # ISO format
            r'(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})',  # dd-mm-yyyy hh:mm:ss
            r'(\d{10})',  # Unix timestamp
            r'(\d{13})',  # Unix timestamp (milliseconds)
        ]
        
        for pattern in patterns:
            match = re.search(pattern, value_str)
            if match:
                try:
                    ts_str = match.group(1)
                    
                    # Try parsing Unix timestamp
                    if ts_str.isdigit():
                        if len(ts_str) == 13:
                            ts = datetime.fromtimestamp(int(ts_str) / 1000)
                        else:
                            ts = datetime.fromtimestamp(int(ts_str))
                        return ts.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Try parsing various date formats
                    for fmt in ['%Y-%m-%d %H:%M:%S', '%m/%d/%Y %H:%M:%S', 
                               '%Y-%m-%dT%H:%M:%S', '%d-%m-%Y %H:%M:%S']:
                        try:
                            ts = datetime.strptime(ts_str, fmt)
                            return ts.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            continue
                except:
                    continue
        
        # Check common timestamp column names
        timestamp_cols = ['timestamp', 'time', 'date', 'datetime', 'created', 'modified', 
                          'last_accessed', 'last_modified', 'event_time', 'log_time']
        for col in timestamp_cols:
            if col in df.columns:
                ts_value = df.at[row_idx, col]
                if not pd.isna(ts_value):
                    return self._extract_timestamp(ts_value, df, row_idx)
        
        return None
    
    def _identify_artifact_type(self, source_name: str, df: pd.DataFrame) -> str:
        """
        Identify the type of forensic artifact
        
        Args:
            source_name: Name of the data source
            df: DataFrame
            
        Returns:
            Artifact type name
        """
        source_lower = source_name.lower()
        cols_lower = [c.lower() for c in df.columns]
        
        # Check for common artifact indicators
        if 'amcache' in source_lower or 'amcache' in ' '.join(cols_lower):
            return 'Amcache'
        elif 'prefetch' in source_lower or 'prefetch' in ' '.join(cols_lower):
            return 'Prefetch'
        elif 'shimcache' in source_lower or 'shimcache' in ' '.join(cols_lower):
            return 'Shimcache'
        elif 'event' in source_lower and 'log' in source_lower:
            return 'Event Log'
        elif 'sysmon' in source_lower:
            return 'Sysmon Event Log'
        elif 'security' in source_lower and 'log' in source_lower:
            return 'Security Event Log'
        elif 'application' in source_lower and 'log' in source_lower:
            return 'Application Event Log'
        elif 'system' in source_lower and 'log' in source_lower:
            return 'System Event Log'
        elif 'process' in source_lower:
            return 'Process List'
        elif 'network' in source_lower or 'connection' in source_lower:
            return 'Network Connection'
        elif 'file' in source_lower:
            return 'File System'
        elif 'registry' in source_lower:
            return 'Registry'
        else:
            return source_name
    
    def _extract_event_id(self, df: pd.DataFrame, row_idx: int) -> Optional[str]:
        """Extract Event ID if this is an event log"""
        event_id_cols = ['event_id', 'eventid', 'event id', 'id', 'eventid_value']
        for col in event_id_cols:
            if col in df.columns:
                event_id = df.at[row_idx, col]
                if not pd.isna(event_id):
                    return str(event_id)
        return None
    
    def _extract_account(self, df: pd.DataFrame, row_idx: int) -> Optional[str]:
        """Extract account/user information"""
        account_cols = ['account', 'user', 'username', 'user_name', 'account_name', 
                       'subject_user_name', 'target_user_name', 'logon_account']
        for col in account_cols:
            if col in df.columns:
                account = df.at[row_idx, col]
                if not pd.isna(account):
                    return str(account)
        return None
    
    def _extract_device_name(self, df: pd.DataFrame, row_idx: int) -> Optional[str]:
        """Extract device/system name"""
        device_cols = ['device', 'computer', 'hostname', 'host_name', 'system', 
                      'machine_name', 'computer_name']
        for col in device_cols:
            if col in df.columns:
                device = df.at[row_idx, col]
                if not pd.isna(device):
                    return str(device)
        return None
    
    def add_from_ioc_match(self, match: Dict[str, Any], df: pd.DataFrame, source_name: str):
        """
        Add timeline entry from IOC match
        
        Args:
            match: IOC match dictionary
            df: DataFrame containing the match
            source_name: Name of the data source
        """
        row_idx = match.get('row_index')
        if row_idx is None:
            return
        
        timestamp = self._extract_timestamp(None, df, row_idx)
        device_name = self._extract_device_name(df, row_idx)
        account = self._extract_account(df, row_idx)
        artifact = self._identify_artifact_type(source_name, df)
        event_id = self._extract_event_id(df, row_idx)
        
        # Create event description
        ioc = match.get('ioc', 'Unknown IOC')
        column = match.get('column', 'Unknown column')
        matched_value = match.get('matched_value', 'Unknown value')
        event = f"IOC Match: {ioc} found in {column}: {matched_value}"
        
        comments = f"Matched IOC ({match.get('ioc_type', 'unknown')}) in {column}"
        level = "Suspicious"  # IOC matches are suspicious
        
        self.timeline_entries.append({
            'Timestamp': timestamp or '',
            'Device Name': device_name or '',
            'Account': account or '',
            'Event': event,
            'Artifact': artifact,
            'Event ID': event_id or '',
            'Analyst': self.analyst_name,
            'Comments': comments,
            'Level': level
        })
    
    def add_from_threat(self, threat: Dict[str, Any], source_name: str, df: Optional[pd.DataFrame] = None, row_idx: Optional[int] = None):
        """
        Add timeline entry from AI-detected threat
        
        Args:
            threat: Threat dictionary from AI analysis
            source_name: Name of the data source
            df: Optional DataFrame if we have row context
            row_idx: Optional row index
        """
        timestamp = None
        device_name = None
        account = None
        event_id = None
        
        if df is not None and row_idx is not None:
            timestamp = self._extract_timestamp(None, df, row_idx)
            device_name = self._extract_device_name(df, row_idx)
            account = self._extract_account(df, row_idx)
            event_id = self._extract_event_id(df, row_idx)
        
        artifact = source_name  # Will be refined if we have df
        if df is not None:
            artifact = self._identify_artifact_type(source_name, df)
        
        event = threat.get('description', threat.get('type', 'Unknown threat'))
        comments = threat.get('recommendation', '')
        if threat.get('indicators'):
            comments += f" Indicators: {', '.join(threat.get('indicators', []))}"
        
        severity = threat.get('severity', 'medium').lower()
        level = "Malicious" if severity in ['critical', 'high'] else "Suspicious"
        
        self.timeline_entries.append({
            'Timestamp': timestamp or '',
            'Device Name': device_name or '',
            'Account': account or '',
            'Event': event,
            'Artifact': artifact,
            'Event ID': event_id or '',
            'Analyst': self.analyst_name,
            'Comments': comments,
            'Level': level
        })
    
    def add_from_anomaly(self, anomaly: Dict[str, Any], df: pd.DataFrame, source_name: str):
        """
        Add timeline entry from pattern-based anomaly
        
        Args:
            anomaly: Anomaly dictionary
            df: DataFrame
            source_name: Name of the data source
        """
        row_idx = anomaly.get('row_index')
        if row_idx is None:
            return
        
        timestamp = self._extract_timestamp(None, df, row_idx)
        device_name = self._extract_device_name(df, row_idx)
        account = self._extract_account(df, row_idx)
        artifact = self._identify_artifact_type(source_name, df)
        event_id = self._extract_event_id(df, row_idx)
        
        event = anomaly.get('description', 'Pattern-based anomaly detected')
        comments = f"Detected {anomaly.get('type', 'unknown')} pattern in {anomaly.get('column', 'unknown')}"
        level = "Suspicious"  # Pattern-based anomalies are suspicious
        
        self.timeline_entries.append({
            'Timestamp': timestamp or '',
            'Device Name': device_name or '',
            'Account': account or '',
            'Event': event,
            'Artifact': artifact,
            'Event ID': event_id or '',
            'Analyst': self.analyst_name,
            'Comments': comments,
            'Level': level
        })
    
    def generate_csv(self, output_path: Optional[Path] = None) -> Path:
        """
        Generate timeline CSV file
        
        Args:
            output_path: Optional output path, defaults to reports/timeline_YYYYMMDD_HHMMSS.csv
            
        Returns:
            Path to generated CSV file
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path("reports") / f"timeline_{timestamp}.csv"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create DataFrame with required columns
        columns = ['Timestamp', 'Device Name', 'Account', 'Event', 'Artifact', 
                  'Event ID', 'Analyst', 'Comments', 'Level']
        
        if not self.timeline_entries:
            # Create empty DataFrame with correct columns
            df_timeline = pd.DataFrame(columns=columns)
        else:
            df_timeline = pd.DataFrame(self.timeline_entries, columns=columns)
        
        # Sort by timestamp if available
        if 'Timestamp' in df_timeline.columns:
            # Separate rows with and without timestamps
            with_ts = df_timeline[df_timeline['Timestamp'] != ''].copy()
            without_ts = df_timeline[df_timeline['Timestamp'] == ''].copy()
            
            if not with_ts.empty:
                with_ts['Timestamp'] = pd.to_datetime(with_ts['Timestamp'], errors='coerce')
                with_ts = with_ts.sort_values('Timestamp')
                with_ts['Timestamp'] = with_ts['Timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
            
            df_timeline = pd.concat([with_ts, without_ts], ignore_index=True)
        
        # Save to CSV
        df_timeline.to_csv(output_path, index=False)
        console.print(f"[green]✓ Timeline CSV saved to: {output_path}[/green]")
        console.print(f"  Total entries: {len(df_timeline)}")
        
        return output_path
