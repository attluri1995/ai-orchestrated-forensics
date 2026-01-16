"""AI Analysis Module - Uses AI to analyze forensic data and detect threats"""

import pandas as pd
from typing import Dict, List, Any, Optional
from rich.console import Console
import json
import os
from pathlib import Path

console = Console()


class AIAnalyzer:
    """AI-powered analyzer for forensic data"""
    
    def __init__(self, use_local_llm: bool = True, model_name: str = "llama3.2"):
        """
        Initialize AI analyzer
        
        Args:
            use_local_llm: Whether to use local LLM (Ollama) or OpenAI
            model_name: Model name for local LLM
        """
        self.use_local_llm = use_local_llm
        self.model_name = model_name
        self.analysis_results = []
        
        # Try to initialize LLM
        if use_local_llm:
            try:
                import ollama
                self.ollama_client = ollama
                console.print(f"[green]✓[/green] Using local LLM: {model_name}")
            except ImportError:
                console.print("[yellow]Ollama not available, falling back to rule-based analysis[/yellow]")
                self.use_local_llm = False
        else:
            # OpenAI setup
            api_key = os.getenv('OPENAI_API_KEY')
            if api_key:
                try:
                    from openai import OpenAI
                    self.openai_client = OpenAI(api_key=api_key)
                    console.print("[green]✓[/green] Using OpenAI API")
                except Exception as e:
                    console.print(f"[yellow]OpenAI setup failed: {e}[/yellow]")
                    self.use_local_llm = True
    
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
            if self.use_local_llm:
                response = self.ollama_client.generate(
                    model=self.model_name,
                    prompt=prompt
                )
                result_text = response['response']
            else:
                response = self.openai_client.chat.completions.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity forensic analyst. Always respond with valid JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3
                )
                result_text = response.choices[0].message.content
            
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

