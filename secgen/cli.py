#!/usr/bin/env python3
"""Command-line interface for SecGen."""

import argparse
import sys
from pathlib import Path

try:
    from secgen.main import SecGen
except ImportError:
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from secgen.main import SecGen


def main():
    parser = argparse.ArgumentParser(description="SecGen: Generate vulnerability reports")
    parser.add_argument("--version", "-v", action="version", version="SecGen 1.0.0")
    parser.add_argument("--input-file", "-i", type=Path, required=True, help="Source code file")
    parser.add_argument("--sarif-report", "-r", type=Path, required=True, help="SARIF report")
    parser.add_argument("--output-file", "-o", type=Path, default="output.txt", help="Output file")
    parser.add_argument("--model", "-m", default="deepseek-chat", help="Model (deepseek-chat, deepseek-coder, gpt-4o-mini)")
    parser.add_argument("--list-vulnerabilities", "-l", action="store_true", help="List vulnerabilities")
    
    args = parser.parse_args()
    
    try:
        secgen = SecGen(model=args.model)
        
        if args.list_vulnerabilities:
            vulns = secgen.list_vulnerabilities(args.sarif_report)
            print(f"Found {len(vulns)} vulnerabilities:")
            for i, v in enumerate(vulns, 1):
                print(f"{i}. {v.type} in {v.file}:{v.line} (severity: {v.severity})")
        else:
            print("🔍 Analyzing... 🧠 Generating...")
            secgen.generate_report(args.input_file, args.sarif_report, args.output_file)
            print(f"✅ Report saved: {args.output_file}")
            
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()