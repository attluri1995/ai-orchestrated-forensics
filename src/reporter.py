"""Reporting Module - Generates reports of findings"""

import json
from typing import List, Dict, Any
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from datetime import datetime

console = Console()


class Reporter:
    """Generates reports of forensic analysis findings"""
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize reporter
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            'critical': 'red',
            'high': 'bright_red',
            'medium': 'yellow',
            'low': 'blue'
        }
        return colors.get(severity.lower(), 'white')
    
    def display_threats_table(self, threats: List[Dict[str, Any]]):
        """Display threats in a formatted table"""
        if not threats:
            console.print("[green]✓ No threats detected![/green]")
            return
        
        table = Table(title="Detected Threats", show_header=True, header_style="bold magenta")
        table.add_column("Source", style="cyan")
        table.add_column("Type", style="white")
        table.add_column("Severity", justify="center")
        table.add_column("Description", style="white", max_width=50)
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_threats = sorted(threats, key=lambda x: severity_order.get(x.get('severity', 'low').lower(), 4))
        
        for threat in sorted_threats:
            severity = threat.get('severity', 'unknown').upper()
            color = self._get_severity_color(threat.get('severity', 'low'))
            table.add_row(
                threat.get('source', 'unknown'),
                threat.get('type', 'unknown'),
                f"[{color}]{severity}[/{color}]",
                threat.get('description', 'No description')[:50]
            )
        
        console.print("\n")
        console.print(table)
        console.print("\n")
    
    def display_analysis_summary(self, analysis_results: List[Dict[str, Any]], anomalies: List[Dict[str, Any]]):
        """Display summary of all analysis results"""
        console.print("\n" + "=" * 80)
        console.print("[bold cyan]FORENSIC ANALYSIS SUMMARY[/bold cyan]")
        console.print("=" * 80 + "\n")
        
        # Pattern-based anomalies
        if anomalies:
            console.print(f"[yellow]Pattern-based Anomalies: {len(anomalies)}[/yellow]")
            for anomaly in anomalies[:10]:  # Show first 10
                console.print(f"  • {anomaly.get('description', 'Unknown')}")
            if len(anomalies) > 10:
                console.print(f"  ... and {len(anomalies) - 10} more")
            console.print()
        
        # AI-detected threats
        all_threats = []
        for analysis in analysis_results:
            all_threats.extend(analysis.get('threats', []))
        
        if all_threats:
            console.print(f"[red]AI-Detected Threats: {len(all_threats)}[/red]")
            self.display_threats_table(all_threats)
        else:
            console.print("[green]✓ No AI-detected threats[/green]\n")
        
        # Analysis summaries
        console.print("[bold]Analysis Summaries:[/bold]\n")
        for analysis in analysis_results:
            source = analysis.get('source', 'unknown')
            summary = analysis.get('summary', 'No summary available')
            confidence = analysis.get('confidence', 'unknown')
            
            panel = Panel(
                f"[white]{summary}[/white]\n\n[dim]Confidence: {confidence}[/dim]",
                title=f"[cyan]{source}[/cyan]",
                border_style="blue"
            )
            console.print(panel)
            console.print()
    
    def generate_json_report(self, analysis_results: List[Dict[str, Any]], 
                           anomalies: List[Dict[str, Any]], 
                           filename: str = None) -> Path:
        """Generate JSON report"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"forensic_report_{timestamp}.json"
        
        report_path = self.output_dir / filename
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_sources_analyzed': len(analysis_results),
                'total_threats': sum(len(a.get('threats', [])) for a in analysis_results),
                'total_anomalies': len(anomalies)
            },
            'pattern_based_anomalies': anomalies,
            'ai_analysis_results': analysis_results,
            'all_threats': []
        }
        
        # Collect all threats
        for analysis in analysis_results:
            source = analysis.get('source', 'unknown')
            for threat in analysis.get('threats', []):
                threat_copy = threat.copy()
                threat_copy['source'] = source
                report['all_threats'].append(threat_copy)
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        console.print(f"[green]✓ JSON report saved to: {report_path}[/green]")
        return report_path
    
    def generate_text_report(self, analysis_results: List[Dict[str, Any]], 
                           anomalies: List[Dict[str, Any]], 
                           filename: str = None) -> Path:
        """Generate human-readable text report"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"forensic_report_{timestamp}.txt"
        
        report_path = self.output_dir / filename
        
        lines = []
        lines.append("=" * 80)
        lines.append("AI ORCHESTRATED FORENSIC ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # Summary
        total_threats = sum(len(a.get('threats', [])) for a in analysis_results)
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Sources Analyzed: {len(analysis_results)}")
        lines.append(f"Pattern-based Anomalies: {len(anomalies)}")
        lines.append(f"AI-Detected Threats: {total_threats}")
        lines.append("")
        
        # Pattern-based anomalies
        if anomalies:
            lines.append("PATTERN-BASED ANOMALIES")
            lines.append("-" * 80)
            for i, anomaly in enumerate(anomalies, 1):
                lines.append(f"{i}. [{anomaly.get('severity', 'unknown').upper()}] {anomaly.get('description', 'Unknown')}")
                lines.append(f"   Source: {anomaly.get('source', 'unknown')}")
                lines.append(f"   Column: {anomaly.get('column', 'unknown')}")
                lines.append(f"   Value: {anomaly.get('value', 'unknown')}")
                lines.append("")
        
        # AI-detected threats
        if total_threats > 0:
            lines.append("AI-DETECTED THREATS")
            lines.append("-" * 80)
            threat_num = 1
            for analysis in analysis_results:
                source = analysis.get('source', 'unknown')
                for threat in analysis.get('threats', []):
                    lines.append(f"{threat_num}. [{threat.get('severity', 'unknown').upper()}] {threat.get('type', 'unknown')}")
                    lines.append(f"   Source: {source}")
                    lines.append(f"   Description: {threat.get('description', 'No description')}")
                    if threat.get('indicators'):
                        lines.append(f"   Indicators: {', '.join(threat.get('indicators', []))}")
                    if threat.get('recommendation'):
                        lines.append(f"   Recommendation: {threat.get('recommendation', 'None')}")
                    lines.append("")
                    threat_num += 1
        
        # Analysis summaries
        lines.append("DETAILED ANALYSIS")
        lines.append("-" * 80)
        for analysis in analysis_results:
            source = analysis.get('source', 'unknown')
            summary = analysis.get('summary', 'No summary available')
            confidence = analysis.get('confidence', 'unknown')
            lines.append(f"\nSource: {source}")
            lines.append(f"Confidence: {confidence}")
            lines.append(f"Summary: {summary}")
            lines.append("")
        
        lines.append("=" * 80)
        
        with open(report_path, 'w') as f:
            f.write('\n'.join(lines))
        
        console.print(f"[green]✓ Text report saved to: {report_path}[/green]")
        return report_path

