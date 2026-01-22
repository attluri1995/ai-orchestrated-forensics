# AI Orchestrated Forensics

An intelligent forensic analysis system that processes CSV files from multiple forensic tools and uses AI to automatically detect threats, anomalies, and indicators of compromise (IOCs).

## Features

- **Google Gemini AI Integration**: Uses Google Gemini for all AI-powered analysis and OSINT intelligence
- **Multi-Format File Support**: Processes CSV, XLSX, and TXT files recursively from directories
- **Interactive Case Input**: Collects analyst name, case type (Ransomware, BEC, Intrusion, Other), threat actor group, and known IOCs
- **OSINT Intelligence Integration**: Automatically retrieves TTPs and IOCs for threat actor groups using Gemini
- **Focused IOC Search**: Searches all files for provided IOCs (IPs, domains, hashes, executables, accounts, etc.)
- **Timeline CSV Generation**: Creates chronological timeline CSV with all identified malicious/suspicious activities
- **Data Normalization**: Standardizes data from different sources for consistent analysis
- **Pattern-Based Detection**: Identifies suspicious patterns using heuristics (file extensions, paths, keywords, etc.)
- **Context-Aware AI Analysis**: Uses case context, IOCs, and TTPs to perform focused threat detection
- **Comprehensive Reporting**: Generates timeline CSV, JSON, and human-readable text reports

## Installation

### Prerequisites

- Python 3.8 or higher
- Google Gemini API key - [Get API Key](https://makersuite.google.com/app/apikey)

### Setup

1. Clone or navigate to this directory:
```bash
cd "AI Orchestrated Forensics"
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up Gemini API key:
```bash
# Option 1: Set as environment variable
export GEMINI_API_KEY=your_api_key_here

# Option 2: Create a .env file
echo "GEMINI_API_KEY=your_api_key_here" > .env
```

## Usage

### Basic Usage

Place your forensic data files (CSV, XLSX, TXT) in a directory, then run:

```bash
python main.py analyze ./path/to/forensic_data
```

The script will:
1. **Ask for Analyst Name**: Enter your name (used in timeline reports)
2. **Case Type**: Select from Ransomware, BEC, Intrusion, or Other
3. **Threat Actor Group**: (Optional) Enter the threat actor group name
4. **Known IOCs**: Paste your known IOCs (IP addresses, domains, hashes, executables, compromised accounts, etc.)
   - You can paste multiple IOCs separated by commas, semicolons, or newlines
   - Example: `192.168.1.100,malicious.exe,evil.com,user@compromised.com`

### With API Key

```bash
python main.py analyze ./forensic_data --api-key YOUR_GEMINI_API_KEY
```

### Test Gemini Connection

```bash
python main.py test-gemini --api-key YOUR_GEMINI_API_KEY
```

### Options

- `data_directory`: Path to directory containing forensic data files (required)
- `--api-key`: Google Gemini API key (optional if GEMINI_API_KEY env var is set)
- `--model-name`: Gemini model name (default: gemini-pro)
- `--output-dir`: Directory to save reports (default: reports)

### Supported File Types

The tool processes files recursively from the specified directory:
- **CSV files** (`.csv`)
- **Excel files** (`.xlsx`)
- **Text files** (`.txt`) - automatically detects delimiters (comma, tab, pipe, semicolon)

## How It Works

1. **Analyst Information**: Collects analyst name for timeline attribution
2. **Case Information Collection**: Interactively collects case type, threat actor group, and known IOCs
3. **File Ingestion**: Recursively scans directory for CSV, XLSX, and TXT files and loads them
4. **Data Processing**: Normalizes column names and detects obvious suspicious patterns
5. **OSINT Intelligence**: If a threat actor group is provided, uses Gemini to retrieve TTPs and IOCs from OSINT sources
6. **Focused IOC Search**: Searches all files for matches with provided and OSINT IOCs
7. **Context-Aware AI Analysis**: Uses Google Gemini AI with case context, IOCs, and TTPs to perform focused analysis, identifying:
   - Matches with known IOCs
   - Activities consistent with the case type
   - TTPs associated with the threat actor group
   - Suspicious files and processes
   - Potential malware indicators
   - Unusual patterns and anomalies
   - Security threats and compromises
8. **Timeline Generation**: Creates chronological CSV timeline with all identified activities
9. **Reporting**: Generates comprehensive reports in JSON and text formats with case information and IOC matches

## Output

The system generates reports in the `reports/` directory:

1. **Timeline CSV** (`timeline_<case_type>.csv`): **Primary output** - Chronological timeline of all identified activities with columns:
   - **Timestamp**: Date/time of event (yyyy-mm-dd hh:mm:ss) or blank if unavailable
   - **Device Name**: System name being analyzed
   - **Account**: User account associated with malicious activity
   - **Event**: Description of the event
   - **Artifact**: Forensic artifact type (Amcache, Prefetch, Shimcache, Event Log, etc.)
   - **Event ID**: Event ID if from event logs
   - **Analyst**: Analyst name
   - **Comments**: Additional context about why the event is suspicious/malicious
   - **Level**: Malicious or Suspicious

2. **JSON Report** (`forensic_report_YYYYMMDD_HHMMSS.json`): Machine-readable format with all findings
3. **Text Report** (`forensic_report_YYYYMMDD_HHMMSS.txt`): Human-readable format with detailed analysis

## Supported Forensic Tools

The system works with CSV, XLSX, and TXT files from any forensic tool, including:
- Volatility memory dumps
- Process monitors
- Network traffic analyzers
- File system scanners
- Registry analyzers
- Event log analyzers (Windows Event Logs, Sysmon, etc.)
- Amcache, Prefetch, Shimcache analyzers
- Any tool that exports to CSV, XLSX, or delimited text files

## Example

```bash
# Analyze forensic data
python main.py analyze ./my_forensic_data

# Output:
# ✓ Found 5 CSV file(s)
# ✓ Loaded process_list.csv (1250 rows)
# ✓ Loaded network_connections.csv (342 rows)
# ...
# 
# Analysis complete!
#   JSON Report: reports/forensic_report_20240101_120000.json
#   Text Report: reports/forensic_report_20240101_120000.txt
```

## Project Structure

```
AI Orchestrated Forensics/
├── main.py                 # Main entry point
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── src/
│   ├── __init__.py
│   ├── case_input.py      # Interactive case information collection
│   ├── csv_ingestion.py   # File loading module (CSV, XLSX, TXT)
│   ├── data_processor.py  # Data processing and pattern detection
│   ├── osint_intelligence.py  # OSINT threat intelligence retrieval (Gemini)
│   ├── focused_search.py  # IOC-focused search module
│   ├── ai_analyzer.py     # AI analysis engine (Gemini)
│   ├── timeline_generator.py  # Timeline CSV generation
│   └── reporter.py        # Report generation
├── sample_data/           # Sample files for testing
└── reports/               # Generated reports (created automatically)
```

## Contributing

Feel free to extend this system with:
- Additional pattern detection rules
- Support for more data formats
- Custom AI prompts for specific forensic scenarios
- Integration with additional LLM providers

## License

This project is provided as-is for forensic analysis purposes.

