"""SecGen-New: Ultra-concise vulnerability report generator."""

from pathlib import Path
from typing import Union, List

from secgen.utils import Vulnerability, parse_sarif
from secgen.llm import LLMInterface


class SecGen:
    """Ultra-simplified vulnerability report generator."""
    
    TEMPLATE = """vuln: <vulnerability-name-here-with-CWE-info> in <file-name-and-line-numbers> (severity: <level-here>)

what: <describe the vulnerability>
where: <locate the vulnerability lines and file>
why: <describe one possible consequence of not resolving this weakness>
how: <explain how an attacker would proceed to exploit this vulnerability>

code-sources: <identify entry points in code where user input enters an application>
code-sinks: <identify actions performed by the application, using user input from a source>

suggested-fix: <code diff file showing the necessary code changes to fix the vulnerability>
explanation-suggested-fix: <explain how the suggested code diff resolves the vulnerability>

method: <write CODEQL if there is any taint information; say UNKNOWN otherwise>"""
    
    SYSTEM_PROMPT = "You are a security expert. Generate a vulnerability report using this exact template:\n\n{template}\n\nFill each section based on the code and analysis. Keep the exact structure."
    
    def __init__(self, model: str = "gpt-4o-mini"):
        self.llm = LLMInterface(model=model)

    def generate_report(self, code_file: Union[str, Path], sarif_file: Union[str, Path], output_file: Union[str, Path]) -> str:
        """Generate vulnerability report from code and SARIF analysis."""
        # Read files
        code = Path(code_file).read_text(encoding='utf-8')
        sarif_content = Path(sarif_file).read_text(encoding='utf-8')
        
        # Parse vulnerabilities
        vulnerabilities = parse_sarif(sarif_content)
        if not vulnerabilities:
            raise ValueError("No vulnerabilities found in SARIF report")
        
        # Generate report
        system_prompt = self.SYSTEM_PROMPT.format(template=self.TEMPLATE)
        user_prompt = f"Code:\n```\n{code}\n```\n\nVulnerabilities found:\n"
        user_prompt += "\n".join(f"{i+1}. {v.type}: {v.description} at {v.file}:{v.line} (severity: {v.severity})" 
                                 for i, v in enumerate(vulnerabilities))
        
        report = self.llm.generate(system_prompt, user_prompt)
        
        # Save and return
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        Path(output_file).write_text(report.strip(), encoding='utf-8')
        return report


    def list_vulnerabilities(self, sarif_file: Union[str, Path]) -> List[Vulnerability]:
        """List vulnerabilities from SARIF file."""
        content = Path(sarif_file).read_text(encoding='utf-8')
        return parse_sarif(content)