# SecGen - Security Vulnerability Scanner

Multi-layered security analysis combining static analysis, taint tracking, and LLM-enhanced detection for C/C++, Python, and other languages.

## Features

- **Taint Analysis**: Track untrusted data flow from sources to sinks  
- **Memory Safety**: Buffer overflows, use-after-free, memory leaks
- **Concurrency Analysis**: Happen-before analysis for race conditions and deadlocks
- **LLM Integration**: AI-powered vulnerability validation and reachability analysis

## Quick Start

```bash
# Install
pip install -r requirements.txt && pip install -e .

# Basic scan
secgen-audit /path/to/project

# With AI enhancement
export OPENAI_API_KEY="your-key"
secgen-audit /path/to/project --model gpt-4 --enable-llm-enhancement
```

## Key Options

```
secgen-audit PROJECT_PATH [options]
  --extensions .py .c .cpp    File types to analyze
  --min-severity high         Filter by severity
  --format json               Output format (text|json|sarif)
  --model gpt-4               LLM model for enhancement
  --enable-llm-enhancement    Enable AI analysis
```

## Vulnerability Types

**Memory Safety (C/C++)**: Buffer overflow, use-after-free, memory leak, null pointer dereference  
**Concurrency (C/C++)**: Race conditions, deadlocks, data races, atomicity violations
**Injection**: SQL injection, command injection, XSS, path traversal  
**Other**: Insecure deserialization, format string bugs, integer overflow

## CI/CD Integration

```yaml
# GitHub Actions
- name: Security Audit
  run: secgen-audit . --format sarif --output security-report.sarif
```

## License

MIT License