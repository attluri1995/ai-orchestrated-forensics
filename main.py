#!/usr/bin/env python3
"""Main entry point for AI Orchestrated Forensics"""

import typer
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

from src.csv_ingestion import CSVIngester
from src.data_processor import DataProcessor
from src.ai_analyzer import AIAnalyzer
from src.reporter import Reporter
from src.case_input import CaseInput
from src.osint_intelligence import OSINTIntelligence
from src.focused_search import FocusedSearcher

app = typer.Typer(help="AI Orchestrated Forensics - Automated threat detection from forensic tool CSVs")
console = Console()


@app.command()
def analyze(
    csv_directory: str = typer.Argument(..., help="Directory containing CSV files from forensic tools"),
    use_local_llm: bool = typer.Option(True, "--local-llm/--openai", help="Use local LLM (Ollama) or OpenAI"),
    model_name: str = typer.Option("llama3.2", help="Model name for local LLM"),
    output_dir: str = typer.Option("reports", help="Directory to save reports")
):
    """
    Analyze forensic CSV files and detect threats
    
    Example:
        python main.py analyze ./forensic_data --local-llm --model-name llama3.2
    """
    console.print(Panel.fit(
        "[bold cyan]AI Orchestrated Forensics[/bold cyan]\n"
        "Automated threat detection from forensic tool CSVs",
        border_style="cyan"
    ))
    console.print()
    
    # Step 0: Collect case information
    console.print("[bold]Step 0: Collecting case information...[/bold]")
    case_input = CaseInput()
    case_info = case_input.collect_case_info()
    case_input.display_summary()
    
    # Step 1: Ingest CSV files
    console.print("[bold]Step 1: Ingesting CSV files...[/bold]")
    ingester = CSVIngester(csv_directory)
    dataframes = ingester.ingest_all()
    
    if not dataframes:
        console.print("[red]No data to analyze. Exiting.[/red]")
        raise typer.Exit(code=1)
    
    # Display summary
    summary = ingester.get_dataframe_summary()
    for name, info in summary.items():
        console.print(f"  [cyan]{name}[/cyan]: {info['rows']:,} rows, {info['columns']} columns")
    console.print()
    
    # Step 2: Process data
    console.print("[bold]Step 2: Processing data...[/bold]")
    processor = DataProcessor(dataframes)
    processed_data = processor.process_all()
    anomalies = processor.get_anomalies()
    
    # Step 3: Get OSINT intelligence
    all_iocs = case_info.get('known_iocs', [])
    ttps = []
    
    if case_info.get('threat_actor_group'):
        console.print("[bold]Step 3: Retrieving OSINT intelligence...[/bold]")
        osint = OSINTIntelligence(use_local_llm=use_local_llm, model_name=model_name)
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
        console.print("[bold]Step 3: Skipping OSINT (no threat actor group provided)...[/bold]\n")
    
    # Step 4: Focused search for IOCs
    if all_iocs:
        console.print("[bold]Step 4: Focused IOC search...[/bold]")
        searcher = FocusedSearcher(processed_data, case_info, all_iocs)
        search_results = searcher.search_all()
        searcher.display_matches_table()
    else:
        console.print("[bold]Step 4: Skipping IOC search (no IOCs provided)...[/bold]\n")
        searcher = None
    
    # Step 5: AI Analysis
    console.print("[bold]Step 5: AI Analysis...[/bold]")
    analyzer = AIAnalyzer(use_local_llm=use_local_llm, model_name=model_name)
    analysis_results = analyzer.analyze_all(
        processed_data, 
        case_info=case_info, 
        iocs=all_iocs if all_iocs else None,
        ttps=ttps if ttps else None
    )
    
    # Step 6: Generate reports
    console.print("[bold]Step 6: Generating reports...[/bold]")
    reporter = Reporter(output_dir=output_dir)
    
    # Display summary
    reporter.display_analysis_summary(analysis_results, anomalies)
    
    # Add search results to report if available
    search_summary = searcher.get_matches_summary() if searcher else {}
    
    # Generate reports
    json_report = reporter.generate_json_report(analysis_results, anomalies, search_summary=search_summary, case_info=case_info)
    text_report = reporter.generate_text_report(analysis_results, anomalies, search_summary=search_summary, case_info=case_info)
    
    console.print("\n[bold green]Analysis complete![/bold green]")
    console.print(f"  JSON Report: {json_report}")
    console.print(f"  Text Report: {text_report}")


@app.command()
def list_models():
    """List available local LLM models (requires Ollama)"""
    try:
        import ollama
        models = ollama.list()
        console.print("[bold]Available Local Models:[/bold]\n")
        for model in models.get('models', []):
            console.print(f"  • {model.get('name', 'unknown')}")
    except ImportError:
        console.print("[red]Ollama not installed. Install it from https://ollama.ai[/red]")
    except Exception as e:
        console.print(f"[red]Error listing models: {e}[/red]")


if __name__ == "__main__":
    app()

