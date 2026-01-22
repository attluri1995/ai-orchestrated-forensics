"""AI Analysis Module - Uses Gemini AI to analyze forensic data and detect threats"""

import pandas as pd
from typing import Dict, List, Any, Optional
from rich.console import Console
import json
import os
from pathlib import Path

console = Console()


class AIAnalyzer:
    """AI-powered analyzer for forensic data using Google Gemini"""
    
    def __init__(self, api_key: Optional[str] = None, model_name: str = "gemini-pro"):
        """
        Initialize AI analyzer with Gemini
        
        Args:
            api_key: Google Gemini API key (or from GEMINI_API_KEY env var)
            model_name: Gemini model name (default: gemini-pro)
        """
        self.model_name = model_name
        self.analysis_results = []
        self.gemini_client = None
        
        # Get API key from parameter or environment
        if api_key:
            self.api_key = api_key
        else:
            self.api_key = os.getenv('GEMINI_API_KEY')
        
        if not self.api_key:
            console.print("[yellow]Warning: GEMINI_API_KEY not found. AI analysis will be limited.[/yellow]")
            console.print("[yellow]Set GEMINI_API_KEY environment variable or pass api_key parameter[/yellow]")
        else:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.gemini_client = genai.GenerativeModel(model_name)
                console.print(f"[green]✓[/green] Using Gemini: {model_name}")
            except ImportError:
                console.print("[red]Error: google-generativeai not installed. Install with: pip install google-generativeai[/red]")
            except Exception as e:
                console.print(f"[yellow]Gemini setup failed: {e}[/yellow]")
    
    def _analyze_with_llm(self, data_summary: str, sample_data: str, source_name: str, 
                          case_info: Optional[Dict[str, Any]] = None, 
                          iocs: Optional[List[str]] = None,
                          ttps: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        """
        Analyze data using LLM
        
        Args:
            data_summary: Summary of the data
            sample_data: Sample rows from the data
            source_name: Name of the data source
            
        Returns:
            Analysis results
        """
        # Build context-aware prompt
        context_parts = []
        
        if case_info:
            case_type = case_info.get('case_type', 'Unknown')
            threat_actor = case_info.get('threat_actor_group')
            context_parts.append(f"Case Type: {case_type}")
            if threat_actor:
                context_parts.append(f"Threat Actor Group: {threat_actor}")
        
        if iocs:
            context_parts.append(f"Known IOCs to search for: {', '.join(iocs[:20])}")
            if len(iocs) > 20:
                context_parts.append(f"... and {len(iocs) - 20} more IOCs")
        
        if ttps:
            context_parts.append(f"Known TTPs: {len(ttps)} TTP(s) associated with threat actor")
            for ttp in ttps[:5]:
                context_parts.append(f"  - {ttp.get('technique', 'Unknown')}: {ttp.get('description', '')}")
        
        context_str = "\n".join(context_parts) if context_parts else "No specific case context provided."
        
        prompt = f"""You are a cybersecurity forensic analyst. Analyze the following forensic data and identify any suspicious, malicious, or anomalous activities.

Case Context:
{context_str}

Data Source: {source_name}

Data Summary:
{data_summary}

Sample Data (first 20 rows):
{sample_data}

Please analyze this data with focus on:
1. Indicators matching the provided IOCs
2. Activities consistent with the case type ({case_info.get('case_type', 'general') if case_info else 'general'})
3. TTPs associated with the threat actor group
4. Any suspicious files, processes, or network activities
5. Potential malware indicators
6. Unusual patterns or anomalies
7. Security threats or compromises

Provide your analysis in JSON format with the following structure:
{{
    "threats": [
        {{
            "type": "malware|suspicious_process|network_anomaly|file_anomaly|other",
            "severity": "critical|high|medium|low",
            "description": "Detailed description",
            "indicators": ["indicator1", "indicator2"],
            "recommendation": "What should be done"
        }}
    ],
    "summary": "Overall assessment",
    "confidence": "high|medium|low"
}}"""

        try:
            if not self.gemini_client:
                # Fallback to rule-based analysis
                return self._rule_based_analysis(data_summary, sample_data, source_name)
            
            # Use Gemini
            response = self.gemini_client.generate_content(
                prompt,
                generation_config={
                    "temperature": 0.3,
                    "top_p": 0.95,
                    "top_k": 40,
                }
            )
            result_text = response.text
            
            # Try to extract JSON from response
            json_start = result_text.find('{')
            json_end = result_text.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                result_text = result_text[json_start:json_end]
            
            analysis = json.loads(result_text)
            return analysis
            
        except json.JSONDecodeError as e:
            console.print(f"[yellow]Warning: Could not parse LLM response as JSON[/yellow]")
            # Fallback to rule-based analysis
            return self._rule_based_analysis(data_summary, sample_data, source_name)
        except Exception as e:
            console.print(f"[red]Error in LLM analysis: {e}[/red]")
            return self._rule_based_analysis(data_summary, sample_data, source_name)
    
    def _rule_based_analysis(self, data_summary: str, sample_data: str, source_name: str) -> Dict[str, Any]:
        """Fallback rule-based analysis"""
        threats = []
        
        # Basic heuristics
        if 'temp' in sample_data.lower() or 'tmp' in sample_data.lower():
            threats.append({
                "type": "file_anomaly",
                "severity": "medium",
                "description": "Files in temporary directories detected",
                "indicators": ["temp directory usage"],
                "recommendation": "Review files in temporary directories"
            })
        
        return {
            "threats": threats,
            "summary": "Rule-based analysis completed. Consider using LLM for deeper analysis.",
            "confidence": "low"
        }
    
    def analyze_dataframe(self, df: pd.DataFrame, source_name: str, 
                         case_info: Optional[Dict[str, Any]] = None,
                         iocs: Optional[List[str]] = None,
                         ttps: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        """
        Analyze a single dataframe
        
        Args:
            df: DataFrame to analyze
            source_name: Name of the data source
            
        Returns:
            Analysis results
        """
        console.print(f"\n[bold]Analyzing {source_name} with AI...[/bold]")
        
        # Create data summary
        data_summary = f"""
Rows: {len(df):,}
Columns: {len(df.columns)}
Column names: {', '.join(df.columns.tolist())}
"""
        
        # Get sample data
        sample_df = df.head(20)
        sample_data = sample_df.to_string(max_rows=20, max_cols=10)
        
        # Analyze with AI
        analysis = self._analyze_with_llm(data_summary, sample_data, source_name, 
                                         case_info=case_info, iocs=iocs, ttps=ttps)
        analysis['source'] = source_name
        
        self.analysis_results.append(analysis)
        
        threat_count = len(analysis.get('threats', []))
        if threat_count > 0:
            console.print(f"  [red]⚠ Found {threat_count} potential threat(s)[/red]")
        else:
            console.print(f"  [green]✓ No obvious threats detected[/green]")
        
        return analysis
    
    def analyze_all(self, processed_data: Dict[str, pd.DataFrame],
                   case_info: Optional[Dict[str, Any]] = None,
                   iocs: Optional[List[str]] = None,
                   ttps: Optional[List[Dict[str, str]]] = None) -> List[Dict[str, Any]]:
        """
        Analyze all processed dataframes
        
        Args:
            processed_data: Dictionary of processed dataframes
            case_info: Case information dictionary
            iocs: List of IOCs to focus on
            ttps: List of TTPs to look for
            
        Returns:
            List of analysis results
        """
        console.print("\n[bold cyan]Starting AI Analysis...[/bold cyan]\n")
        
        if case_info:
            console.print(f"Case Type: [cyan]{case_info.get('case_type', 'Unknown')}[/cyan]")
        if iocs:
            console.print(f"Focusing on: [yellow]{len(iocs)} IOC(s)[/yellow]")
        if ttps:
            console.print(f"Known TTPs: [yellow]{len(ttps)} TTP(s)[/yellow]")
        console.print()
        
        for name, df in processed_data.items():
            self.analyze_dataframe(df, name, case_info=case_info, iocs=iocs, ttps=ttps)
        
        console.print(f"\n[green]Analysis complete for {len(self.analysis_results)} data source(s)[/green]\n")
        return self.analysis_results
    
    def get_all_threats(self) -> List[Dict[str, Any]]:
        """Get all detected threats from all analyses"""
        all_threats = []
        for analysis in self.analysis_results:
            source = analysis.get('source', 'unknown')
            for threat in analysis.get('threats', []):
                threat['source'] = source
                all_threats.append(threat)
        return all_threats

