#!/usr/bin/env python3
"""Main entry point for AI Orchestrated Forensics"""

import typer
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

from src.csv_ingestion import FileIngester
from src.data_processor import DataProcessor
from src.ai_analyzer import AIAnalyzer
from src.reporter import Reporter
from src.case_input import CaseInput
from src.osint_intelligence import OSINTIntelligence
from src.focused_search import FocusedSearcher
from src.timeline_generator import TimelineGenerator
from rich.prompt import Prompt
import os

app = typer.Typer(help="AI Orchestrated Forensics - Automated threat detection from forensic tool CSVs")
console = Console()


@app.command()
def analyze(
    data_directory: str = typer.Argument(..., help="Directory containing forensic data files (CSV, XLSX, TXT)"),
    gemini_api_key: str = typer.Option(None, "--api-key", help="Google Gemini API key (or set GEMINI_API_KEY env var)"),
    model_name: str = typer.Option("gemini-pro", help="Gemini model name"),
    output_dir: str = typer.Option("reports", help="Directory to save reports")
):
    """
    Analyze forensic data files and detect threats
    
    Example:
        python main.py analyze ./forensic_data --api-key YOUR_API_KEY
    """
    console.print(Panel.fit(
        "[bold cyan]AI Orchestrated Forensics[/bold cyan]\n"
        "Automated threat detection from forensic tool outputs",
        border_style="cyan"
    ))
    console.print()
    
    # Step 0: Get analyst name
    console.print("[bold]Step 0: Analyst Information[/bold]")
    analyst_name = Prompt.ask("Analyst Name", default="Unknown Analyst")
    console.print(f"[green]✓[/green] Analyst: {analyst_name}\n")
    
    # Step 1: Collect case information
    console.print("[bold]Step 1: Collecting case information...[/bold]")
    case_input = CaseInput()
    case_info = case_input.collect_case_info()
    case_input.display_summary()
    
    # Step 2: Ingest files (CSV, XLSX, TXT)
    console.print("[bold]Step 2: Ingesting forensic data files...[/bold]")
    ingester = FileIngester(data_directory)
    dataframes = ingester.ingest_all()
    
    if not dataframes:
        console.print("[red]No data to analyze. Exiting.[/red]")
        raise typer.Exit(code=1)
    
    # Display summary
    summary = ingester.get_dataframe_summary()
    for name, info in summary.items():
        console.print(f"  [cyan]{name}[/cyan]: {info['rows']:,} rows, {info['columns']} columns")
    console.print()
    
    # Step 3: Process data
    console.print("[bold]Step 3: Processing data...[/bold]")
    processor = DataProcessor(dataframes)
    processed_data = processor.process_all()
    anomalies = processor.get_anomalies()
    
    # Step 4: Get OSINT intelligence
    all_iocs = case_info.get('known_iocs', [])
    ttps = []
    
    if case_info.get('threat_actor_group'):
        console.print("[bold]Step 4: Retrieving OSINT intelligence...[/bold]")
        osint = OSINTIntelligence(api_key=gemini_api_key, model_name=model_name)
        intelligence = osint.get_threat_actor_intelligence(case_info['threat_actor_group'])
        
        if intelligence:
            # Get OSINT IOCs
            osint_iocs = osint.get_all_iocs(intelligence)
            all_iocs = osint.combine_iocs(case_info.get('known_iocs', []), osint_iocs)
            
            # Get TTPs
            ttps = osint.get_all_ttps(intelligence)
            
            console.print(f"[green]✓[/green] Combined {len(all_iocs)} total IOC(s) (user + OSINT)")
            console.print()
    else:
        console.print("[bold]Step 4: Skipping OSINT (no threat actor group provided)...[/bold]\n")
    
    # Step 5: Focused search for IOCs
    searcher = None
    if all_iocs:
        console.print("[bold]Step 5: Focused IOC search...[/bold]")
        searcher = FocusedSearcher(processed_data, case_info, all_iocs)
        search_results = searcher.search_all()
        searcher.display_matches_table()
    else:
        console.print("[bold]Step 5: Skipping IOC search (no IOCs provided)...[/bold]\n")
    
    # Step 6: AI Analysis
    console.print("[bold]Step 6: AI Analysis with Gemini...[/bold]")
    analyzer = AIAnalyzer(api_key=gemini_api_key, model_name=model_name)
    analysis_results = analyzer.analyze_all(
        processed_data, 
        case_info=case_info, 
        iocs=all_iocs if all_iocs else None,
        ttps=ttps if ttps else None
    )
    
    # Step 7: Generate timeline CSV
    console.print("[bold]Step 7: Generating timeline CSV...[/bold]")
    timeline_gen = TimelineGenerator(analyst_name=analyst_name)
    
    # Add entries from IOC matches
    if searcher:
        for source_name, matches in searcher.search_results.items():
            df = processed_data.get(source_name)
            if df is not None:
                for match in matches:
                    timeline_gen.add_from_ioc_match(match, df, source_name)
    
    # Add entries from AI-detected threats
    for analysis in analysis_results:
        source_name = analysis.get('source', 'unknown')
        df = processed_data.get(source_name)
        for threat in analysis.get('threats', []):
            timeline_gen.add_from_threat(threat, source_name, df)
    
    # Add entries from pattern-based anomalies
    for anomaly in anomalies:
        source_name = anomaly.get('source', 'unknown')
        df = processed_data.get(source_name)
        if df is not None:
            timeline_gen.add_from_anomaly(anomaly, df, source_name)
    
    # Generate timeline CSV
    timeline_csv = timeline_gen.generate_csv(Path(output_dir) / f"timeline_{case_info.get('case_type', 'analysis').lower()}.csv")
    
    # Step 8: Generate other reports
    console.print("[bold]Step 8: Generating additional reports...[/bold]")
    reporter = Reporter(output_dir=output_dir)
    
    # Display summary
    reporter.display_analysis_summary(analysis_results, anomalies)
    
    # Add search results to report if available
    search_summary = searcher.get_matches_summary() if searcher else {}
    
    # Generate reports
    json_report = reporter.generate_json_report(analysis_results, anomalies, search_summary=search_summary, case_info=case_info)
    text_report = reporter.generate_text_report(analysis_results, anomalies, search_summary=search_summary, case_info=case_info)
    
    console.print("\n[bold green]Analysis complete![/bold green]")
    console.print(f"  [bold]Timeline CSV:[/bold] {timeline_csv}")
    console.print(f"  JSON Report: {json_report}")
    console.print(f"  Text Report: {text_report}")


@app.command()
def test_gemini(
    api_key: str = typer.Option(None, "--api-key", help="Google Gemini API key (or set GEMINI_API_KEY env var)")
):
    """Test Gemini API connection"""
    test_key = api_key or os.getenv('GEMINI_API_KEY')
    if not test_key:
        console.print("[red]Error: GEMINI_API_KEY not provided[/red]")
        console.print("Set it as environment variable or pass --api-key")
        raise typer.Exit(code=1)
    
    try:
        import google.generativeai as genai
        genai.configure(api_key=test_key)
        model = genai.GenerativeModel("gemini-pro")
        response = model.generate_content("Say 'Hello' if you can read this.")
        console.print(f"[green]✓ Gemini API connection successful![/green]")
        console.print(f"Response: {response.text}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()

