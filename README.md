# AI Orchestrated Forensics

An intelligent forensic analysis system that processes CSV files from multiple forensic tools and uses AI to automatically detect threats, anomalies, and indicators of compromise (IOCs).

## Features

- **Interactive Case Input**: Collects case type (Ransomware, BEC, Intrusion, Other), threat actor group, and known IOCs
- **OSINT Intelligence Integration**: Automatically retrieves TTPs and IOCs for threat actor groups from OSINT sources
- **Focused IOC Search**: Searches all CSV files for provided IOCs (IPs, domains, hashes, executables, accounts, etc.)
- **Multi-Source CSV Ingestion**: Automatically discovers and loads CSV files from various forensic tools
- **Data Normalization**: Standardizes data from different sources for consistent analysis
- **Pattern-Based Detection**: Identifies suspicious patterns using heuristics (file extensions, paths, keywords, etc.)
- **Context-Aware AI Analysis**: Uses case context, IOCs, and TTPs to perform focused threat detection
- **Comprehensive Reporting**: Generates both JSON and human-readable text reports with case information

## Installation

### Prerequisites

- Python 3.8 or higher
- (Optional) Ollama for local LLM support - [Install Ollama](https://ollama.ai)

### Setup

1. Clone or navigate to this directory:
```bash
cd "AI Orchestrated Forensics"
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Set up local LLM with Ollama:
```bash
# Install Ollama from https://ollama.ai
# Then pull a model:
ollama pull llama3.2
# or
ollama pull mistral
```

4. (Optional) For OpenAI support, create a `.env` file:
```bash
echo "OPENAI_API_KEY=your_api_key_here" > .env
```

## Usage

### Basic Usage

Place your CSV files from forensic tools in a directory, then run:

```bash
python main.py analyze ./path/to/csv/files
```

The script will interactively prompt you for:
1. **Case Type**: Select from Ransomware, BEC, Intrusion, or Other
2. **Threat Actor Group**: (Optional) Enter the threat actor group name
3. **Known IOCs**: Paste your known IOCs (IP addresses, domains, hashes, executables, compromised accounts, etc.)
   - You can paste multiple IOCs separated by commas, semicolons, or newlines
   - Example: `192.168.1.100,malicious.exe,evil.com,user@compromised.com`

### Using Local LLM (Default)

```bash
python main.py analyze ./forensic_data --local-llm --model-name llama3.2
```

### Using OpenAI

```bash
python main.py analyze ./forensic_data --openai
```

### List Available Models

```bash
python main.py list-models
```

### Options

- `csv_directory`: Path to directory containing CSV files (required)
- `--local-llm/--openai`: Choose between local LLM or OpenAI (default: local-llm)
- `--model-name`: Model name for local LLM (default: llama3.2)
- `--output-dir`: Directory to save reports (default: reports)

## How It Works

1. **Case Information Collection**: Interactively collects case type, threat actor group, and known IOCs
2. **CSV Ingestion**: Scans the specified directory for CSV files and loads them
3. **Data Processing**: Normalizes column names and detects obvious suspicious patterns
4. **OSINT Intelligence**: If a threat actor group is provided, retrieves TTPs and IOCs from OSINT sources
5. **Focused IOC Search**: Searches all CSV files for matches with provided and OSINT IOCs
6. **Context-Aware AI Analysis**: Uses AI with case context, IOCs, and TTPs to perform focused analysis, identifying:
   - Matches with known IOCs
   - Activities consistent with the case type
   - TTPs associated with the threat actor group
   - Suspicious files and processes
   - Potential malware indicators
   - Unusual patterns and anomalies
   - Security threats and compromises
7. **Reporting**: Generates comprehensive reports in JSON and text formats with case information and IOC matches

## Output

The system generates two types of reports in the `reports/` directory:

1. **JSON Report** (`forensic_report_YYYYMMDD_HHMMSS.json`): Machine-readable format with all findings
2. **Text Report** (`forensic_report_YYYYMMDD_HHMMSS.txt`): Human-readable format with detailed analysis

## Supported Forensic Tools

The system works with CSV files from any forensic tool, including:
- Volatility memory dumps
- Process monitors
- Network traffic analyzers
- File system scanners
- Registry analyzers
- Log analyzers
- Any tool that exports to CSV

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
│   ├── csv_ingestion.py   # CSV loading module
│   ├── data_processor.py  # Data processing and pattern detection
│   ├── osint_intelligence.py  # OSINT threat intelligence retrieval
│   ├── focused_search.py  # IOC-focused search module
│   ├── ai_analyzer.py     # AI analysis engine
│   └── reporter.py        # Report generation
├── sample_data/           # Sample CSV files for testing
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

