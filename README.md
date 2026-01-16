# AI Orchestrated Forensics

An intelligent forensic analysis system that processes CSV files from multiple forensic tools and uses AI to automatically detect threats, anomalies, and indicators of compromise (IOCs).

## Features

- **Multi-Source CSV Ingestion**: Automatically discovers and loads CSV files from various forensic tools
- **Data Normalization**: Standardizes data from different sources for consistent analysis
- **Pattern-Based Detection**: Identifies suspicious patterns using heuristics (file extensions, paths, keywords, etc.)
- **AI-Powered Analysis**: Uses local LLMs (via Ollama) or OpenAI to perform deep analysis and threat detection
- **Comprehensive Reporting**: Generates both JSON and human-readable text reports

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

1. **CSV Ingestion**: Scans the specified directory for CSV files and loads them
2. **Data Processing**: Normalizes column names and detects obvious suspicious patterns
3. **AI Analysis**: Uses AI to perform deep analysis of the data, identifying:
   - Suspicious files and processes
   - Potential malware indicators
   - Unusual patterns and anomalies
   - Security threats and compromises
   - Indicators of Compromise (IOCs)
4. **Reporting**: Generates comprehensive reports in JSON and text formats

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
│   ├── csv_ingestion.py   # CSV loading module
│   ├── data_processor.py  # Data processing and pattern detection
│   ├── ai_analyzer.py     # AI analysis engine
│   └── reporter.py        # Report generation
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

