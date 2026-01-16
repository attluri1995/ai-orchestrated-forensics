#!/bin/bash
# Example usage script for AI Orchestrated Forensics

echo "AI Orchestrated Forensics - Example Usage"
echo "=========================================="
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

# Check if dependencies are installed
if ! python3 -c "import pandas" &> /dev/null; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
fi

# Create example directory structure
echo "Creating example directory structure..."
mkdir -p example_forensic_data

echo ""
echo "To use this tool:"
echo "1. Place your CSV files from forensic tools in a directory"
echo "2. Run: python3 main.py analyze ./path/to/csv/files"
echo ""
echo "Example:"
echo "  python3 main.py analyze ./example_forensic_data"
echo ""
echo "For help:"
echo "  python3 main.py --help"
echo ""

