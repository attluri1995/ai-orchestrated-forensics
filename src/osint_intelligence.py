"""OSINT Intelligence Module - Retrieves threat actor TTPs and IOCs from OSINT sources using Gemini"""

from typing import Dict, List, Optional, Any
from rich.console import Console
import json
import re
import os

console = Console()


class OSINTIntelligence:
    """Retrieves threat intelligence from OSINT sources using Google Gemini"""
    
    def __init__(self, api_key: Optional[str] = None, model_name: str = "gemini-pro"):
        """
        Initialize OSINT intelligence gatherer with Gemini
        
        Args:
            api_key: Google Gemini API key (or from GEMINI_API_KEY env var)
            model_name: Gemini model name (default: gemini-pro)
        """
        self.model_name = model_name
        self.intelligence_cache = {}
        self.gemini_client = None
        
        # Get API key from parameter or environment
        if api_key:
            self.api_key = api_key
        else:
            self.api_key = os.getenv('GEMINI_API_KEY')
        
        if not self.api_key:
            console.print("[yellow]Warning: GEMINI_API_KEY not found. OSINT research will be limited.[/yellow]")
            self.llm_available = False
        else:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.gemini_client = genai.GenerativeModel(model_name)
                self.llm_available = True
            except ImportError:
                console.print("[red]Error: google-generativeai not installed[/red]")
                self.llm_available = False
            except Exception as e:
                console.print(f"[yellow]Gemini setup failed: {e}[/yellow]")
                self.llm_available = False
    
    def _query_llm_for_intelligence(self, threat_actor_group: str) -> Dict[str, Any]:
        """
        Query LLM for threat actor intelligence
        
        Args:
            threat_actor_group: Name of the threat actor group
            
        Returns:
            Dictionary with TTPs and IOCs
        """
        if not self.llm_available:
            return {}
        
        prompt = f"""You are a cybersecurity threat intelligence analyst. Research and provide information about the threat actor group: {threat_actor_group}

Please provide:
1. Known TTPs (Tactics, Techniques, and Procedures) used by this group
2. Known IOCs (Indicators of Compromise) associated with this group:
   - IP addresses
   - Domain names
   - File hashes (MD5, SHA1, SHA256)
   - Email addresses
   - Executable names
   - Registry keys
   - User agents
   - Any other indicators

Provide your response in JSON format:
{{
    "threat_actor": "{threat_actor_group}",
    "ttps": [
        {{
            "tactic": "Tactic name",
            "technique": "Technique ID or name",
            "description": "Description of the TTP"
        }}
    ],
    "iocs": {{
        "ip_addresses": ["ip1", "ip2"],
        "domains": ["domain1.com", "domain2.com"],
        "file_hashes": ["hash1", "hash2"],
        "email_addresses": ["email1@example.com"],
        "executables": ["executable1.exe", "executable2.exe"],
        "registry_keys": ["registry\\key\\path"],
        "user_agents": ["user agent string"],
        "other": ["other indicator"]
    }},
    "sources": ["source1", "source2"]
}}"""

        try:
            if not self.gemini_client:
                return {}
            
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
            
            # Extract JSON
            json_start = result_text.find('{')
            json_end = result_text.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                result_text = result_text[json_start:json_end]
            
            intelligence = json.loads(result_text)
            return intelligence
            
        except json.JSONDecodeError:
            console.print(f"[yellow]Warning: Could not parse OSINT intelligence as JSON[/yellow]")
            return {}
        except Exception as e:
            console.print(f"[yellow]Warning: Error retrieving OSINT intelligence: {e}[/yellow]")
            return {}
    
    def get_threat_actor_intelligence(self, threat_actor_group: str) -> Dict[str, Any]:
        """
        Get intelligence for a threat actor group
        
        Args:
            threat_actor_group: Name of the threat actor group
            
        Returns:
            Dictionary with TTPs and IOCs
        """
        if not threat_actor_group:
            return {}
        
        # Check cache
        if threat_actor_group in self.intelligence_cache:
            return self.intelligence_cache[threat_actor_group]
        
        console.print(f"\n[bold]Retrieving OSINT intelligence for: [cyan]{threat_actor_group}[/cyan][/bold]")
        
        intelligence = self._query_llm_for_intelligence(threat_actor_group)
        
        if intelligence:
            # Cache the results
            self.intelligence_cache[threat_actor_group] = intelligence
            
            # Display summary
            ttps_count = len(intelligence.get('ttps', []))
            iocs = intelligence.get('iocs', {})
            total_iocs = sum(len(v) if isinstance(v, list) else 0 for v in iocs.values())
            
            console.print(f"  [green]✓[/green] Retrieved {ttps_count} TTP(s) and {total_iocs} IOC(s)")
            
            if ttps_count > 0:
                console.print("  [dim]TTPs:[/dim]")
                for ttp in intelligence.get('ttps', [])[:3]:
                    technique = ttp.get('technique', 'Unknown')
                    console.print(f"    • {technique}")
                if ttps_count > 3:
                    console.print(f"    ... and {ttps_count - 3} more")
        else:
            console.print(f"  [yellow]⚠ No intelligence found for {threat_actor_group}[/yellow]")
        
        return intelligence
    
    def get_all_iocs(self, intelligence: Dict[str, Any]) -> List[str]:
        """
        Extract all IOCs from intelligence data
        
        Args:
            intelligence: Intelligence dictionary
            
        Returns:
            List of all IOCs
        """
        all_iocs = []
        iocs = intelligence.get('iocs', {})
        
        for ioc_type, ioc_list in iocs.items():
            if isinstance(ioc_list, list):
                all_iocs.extend(ioc_list)
            elif isinstance(ioc_list, str):
                all_iocs.append(ioc_list)
        
        return all_iocs
    
    def get_all_ttps(self, intelligence: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Extract all TTPs from intelligence data
        
        Args:
            intelligence: Intelligence dictionary
            
        Returns:
            List of TTP dictionaries
        """
        return intelligence.get('ttps', [])
    
    def combine_iocs(self, known_iocs: List[str], osint_iocs: List[str]) -> List[str]:
        """
        Combine known IOCs with OSINT IOCs
        
        Args:
            known_iocs: User-provided IOCs
            osint_iocs: OSINT-retrieved IOCs
            
        Returns:
            Combined and deduplicated list of IOCs
        """
        all_iocs = known_iocs + osint_iocs
        # Deduplicate while preserving order
        seen = set()
        unique_iocs = []
        for ioc in all_iocs:
            ioc_lower = ioc.lower().strip()
            if ioc_lower and ioc_lower not in seen:
                seen.add(ioc_lower)
                unique_iocs.append(ioc)
        return unique_iocs

