# SecGen

Transform SARIF static analysis results into clear, actionable vulnerability reports for easier triage and remediation.

This is a personal reimplementation of the approach from "ASE'25 Interpretable Vulnerability Detection Reports".

## Installation

```bash
pip install -r requirements.txt
pip install -e .
```

## Quick Start

Set your OpenAI/DEEPSEEK API key:
```bash
export OPENAI_API_KEY="your-api-key-here"
export DEEPSEEK_API_KEY="your-api-key-here"
```

Generate a vulnerability report:
```bash
secgen --sarif-report samples/codeql/results_FormAI_1007.sarif --input-file samples/FormAI_1007.c -o report.txt
```

## Usage

```bash
secgen [OPTIONS]

Options:
  -i, --input-file PATH     Path to vulnerable source code (required)
  -r, --sarif-report PATH   Path to SARIF analysis report (required)  
  -o, --output-file PATH    Path for generated report (required)
  -m, --model TEXT          Model to use (default: deepseek-chat)
  -l, --list-vulnerabilities  Just list vulnerabilities without generating report
  -v, --version            Show version
  -h, --help               Show help message
```

## Report Format

Generates reports in the standard SECGEN format:

```
vuln: <vulnerability-name-with-CWE> in <file:line> (severity: <level>)

what: <vulnerability description>
where: <exact location>  
why: <potential consequences>
how: <exploitation method>

code-sources: <input entry points>
code-sinks: <vulnerable operations>

suggested-fix: <code diff>
explanation-suggested-fix: <fix explanation>

method: <detection method>
```

## License

MIT License - see original project for details.
