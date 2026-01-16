"""Case Input Module - Interactive input for case details"""

from typing import Dict, List, Optional
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.text import Text

console = Console()

CASE_TYPES = ["Ransomware", "BEC", "Intrusion", "Other"]


class CaseInput:
    """Handles interactive case input from user"""
    
    def __init__(self):
        self.case_type: Optional[str] = None
        self.threat_actor_group: Optional[str] = None
        self.known_iocs: List[str] = []
    
    def collect_case_info(self) -> Dict[str, any]:
        """
        Collect case information interactively
        
        Returns:
            Dictionary with case information
        """
        console.print(Panel.fit(
            "[bold cyan]Case Information Input[/bold cyan]\n"
            "Please provide details about the case",
            border_style="cyan"
        ))
        console.print()
        
        # Case Type
        console.print("[bold]Case Type Selection:[/bold]")
        for i, case_type in enumerate(CASE_TYPES, 1):
            console.print(f"  {i}. {case_type}")
        console.print()
        
        while True:
            choice = Prompt.ask(
                "Select case type",
                choices=[str(i) for i in range(1, len(CASE_TYPES) + 1)] + [c.lower() for c in CASE_TYPES],
                default="1"
            )
            
            if choice.isdigit() and 1 <= int(choice) <= len(CASE_TYPES):
                self.case_type = CASE_TYPES[int(choice) - 1]
                break
            elif choice.lower() in [c.lower() for c in CASE_TYPES]:
                self.case_type = next(c for c in CASE_TYPES if c.lower() == choice.lower())
                break
            else:
                console.print("[red]Invalid choice. Please try again.[/red]")
        
        console.print(f"[green]✓[/green] Case Type: {self.case_type}\n")
        
        # Threat Actor Group
        console.print("[bold]Threat Actor Group:[/bold]")
        console.print("  Enter the threat actor group name (or press Enter to skip)")
        threat_actor = Prompt.ask("Threat Actor Group", default="")
        
        if threat_actor.strip():
            self.threat_actor_group = threat_actor.strip()
            console.print(f"[green]✓[/green] Threat Actor Group: {self.threat_actor_group}\n")
        else:
            console.print("[yellow]⚠ Threat Actor Group: Not provided[/yellow]\n")
        
        # Known IOCs
        console.print("[bold]Known IOCs (Indicators of Compromise):[/bold]")
        console.print("  You can paste multiple IOCs separated by commas, newlines, semicolons, or pipes (|)")
        console.print("  Examples: IP addresses, compromised accounts, file hashes, domain names, executables")
        console.print("  You can paste a large list at once - just separate them with commas or newlines\n")
        
        ioc_text = Prompt.ask(
            "Paste IOCs (comma/semicolon/pipe separated, or press Enter to skip)",
            default=""
        )
        
        if not ioc_text.strip():
            console.print("[yellow]⚠ No IOCs provided[/yellow]\n")
            self.known_iocs = []
            return self.to_dict()
        
        # Parse IOCs from the input - handle multiple delimiters
        all_iocs = []
        
        # First, try splitting by newlines (if user pasted multi-line)
        if '\n' in ioc_text:
            lines = ioc_text.split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # Then split by other delimiters
                for delimiter in [',', ';', '|']:
                    if delimiter in line:
                        all_iocs.extend([ioc.strip() for ioc in line.split(delimiter) if ioc.strip()])
                        break
                else:
                    all_iocs.append(line)
        else:
            # Single line - split by delimiters
            for delimiter in [',', ';', '|']:
                if delimiter in ioc_text:
                    all_iocs.extend([ioc.strip() for ioc in ioc_text.split(delimiter) if ioc.strip()])
                    break
            else:
                # No delimiter found, treat as single IOC
                all_iocs.append(ioc_text.strip())
        
        # Clean and deduplicate IOCs
        self.known_iocs = list(set([ioc.strip() for ioc in all_iocs if ioc.strip()]))
        
        if self.known_iocs:
            console.print(f"[green]✓[/green] Collected {len(self.known_iocs)} IOC(s)\n")
            console.print("[dim]Sample IOCs:[/dim]")
            for ioc in self.known_iocs[:5]:
                console.print(f"  • {ioc}")
            if len(self.known_iocs) > 5:
                console.print(f"  ... and {len(self.known_iocs) - 5} more\n")
        else:
            console.print("[yellow]⚠ No IOCs provided[/yellow]\n")
        
        return self.to_dict()
    
    def to_dict(self) -> Dict[str, any]:
        """Convert to dictionary"""
        return {
            'case_type': self.case_type,
            'threat_actor_group': self.threat_actor_group,
            'known_iocs': self.known_iocs
        }
    
    def display_summary(self):
        """Display summary of collected case information"""
        console.print(Panel(
            f"[bold]Case Summary[/bold]\n\n"
            f"Case Type: [cyan]{self.case_type}[/cyan]\n"
            f"Threat Actor Group: [cyan]{self.threat_actor_group or 'Not provided'}[/cyan]\n"
            f"Known IOCs: [cyan]{len(self.known_iocs)} IOC(s)[/cyan]",
            border_style="blue"
        ))
        console.print()

