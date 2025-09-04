
import ast
import base64
import inspect
import json
import keyword
import os
import re
import time
from functools import lru_cache
from io import BytesIO
from textwrap import dedent
from typing import Any


__all__ = ["AgentError"]


def escape_code_brackets(text: str) -> str:
    """Escapes square brackets in code segments while preserving Rich styling tags."""

    def replace_bracketed_content(match):
        content = match.group(1)
        cleaned = re.sub(
            r"bold|red|green|blue|yellow|magenta|cyan|white|black|italic|dim|\s|#[0-9a-fA-F]{6}", "", content
        )
        return f"\\[{content}\\]" if cleaned.strip() else f"[{content}]"

    return re.sub(r"\[([^\]]*)\]", replace_bracketed_content, text)


class AgentError(Exception):
    def __init__(self, message, logger: "AgentLogger"):
        super().__init__(message)
        self.message = message
        logger.log_error(message)

    def dict(self) -> dict[str, str]:
        return {"type": self.__class__.__name__, "message": str(self.message)}


class AgentParsingError(AgentError):
    pass


class AgentExecutionError(AgentError):
    pass


class AgentMaxStepsError(AgentError):
    pass


class AgentToolCallError(AgentExecutionError):
    pass


class AgentToolExecutionError(AgentExecutionError):
    pass


class AgentGenerationError(AgentError):
    pass


def make_json_serializable(obj: Any) -> Any:
    if obj is None:
        return None
    elif isinstance(obj, (str, int, float, bool)):
        if isinstance(obj, str) and ((obj.startswith("{") and obj.endswith("}")) or (obj.startswith("[") and obj.endswith("]"))):
            try:
                return make_json_serializable(json.loads(obj))
            except json.JSONDecodeError:
                pass
        return obj
    elif isinstance(obj, (list, tuple)):
        return [make_json_serializable(item) for item in obj]
    elif isinstance(obj, dict):
        return {str(k): make_json_serializable(v) for k, v in obj.items()}
    elif hasattr(obj, "__dict__"):
        return {"_type": obj.__class__.__name__, **{k: make_json_serializable(v) for k, v in obj.__dict__.items()}}
    else:
        return str(obj)


def parse_json_blob(json_blob: str) -> tuple[dict[str, str], str]:
    try:
        start = json_blob.find("{")
        end = [m.start() for m in re.finditer("}", json_blob)][-1]
        json_str = json_blob[start:end + 1]
        return json.loads(json_str, strict=False), json_blob[:start]
    except IndexError:
        raise ValueError("The model output does not contain any JSON blob.")
    except json.JSONDecodeError as e:
        if json_blob[e.pos - 1:e.pos + 2] == "},\n":
            raise ValueError("JSON is invalid: you probably tried to provide multiple tool calls in one action. PROVIDE ONLY ONE TOOL CALL.")
        raise ValueError(f"The JSON blob you used is invalid due to the following error: {e}.\nJSON blob was: {json_blob}, decoding failed on that specific part of the blob:\n'{json_blob[e.pos - 4:e.pos + 5]}'.")


def extract_code_from_text(text: str, code_block_tags: tuple[str, str]) -> str | None:
    pattern = rf"{code_block_tags[0]}(.*?){code_block_tags[1]}"
    matches = re.findall(pattern, text, re.DOTALL)
    return "\n\n".join(match.strip() for match in matches) if matches else None


def parse_code_blobs(text: str, code_block_tags: tuple[str, str]) -> str:
    matches = extract_code_from_text(text, code_block_tags)
    if not matches:
        matches = extract_code_from_text(text, ("```(?:python|py)", "\n```"))
    if matches:
        return matches
    
    try:
        ast.parse(text)
        return text
    except SyntaxError:
        pass

    error_msg = f"Your code snippet is invalid, because the regex pattern {code_block_tags[0]}(.*?){code_block_tags[1]} was not found in it.\nHere is your code snippet:\n{text}"
    if "final" in text and "answer" in text:
        error_msg += f"\nIt seems like you're trying to return the final answer, you can do it as follows:\n{code_block_tags[0]}\nfinal_answer(\"YOUR FINAL ANSWER HERE\")\n{code_block_tags[1]}"
    else:
        error_msg += f"\nMake sure to include code with the correct pattern, for instance:\nThoughts: Your thoughts\n{code_block_tags[0]}\n# Your python code here\n{code_block_tags[1]}"
    raise ValueError(error_msg)


def truncate_content(content: str, max_length: int = 20000) -> str:
    if len(content) <= max_length:
        return content
    return (
        content[:max_length // 2]
        + f"\n..._This content has been truncated to stay below {max_length} characters_...\n"
        + content[-max_length // 2:]
    )


class ImportFinder(ast.NodeVisitor):
    def __init__(self):
        self.packages = set()

    def visit_Import(self, node):
        for alias in node.names:
            # Get the base package name (before any dots)
            base_package = alias.name.split(".")[0]
            self.packages.add(base_package)

    def visit_ImportFrom(self, node):
        if node.module:  # for "from x import y" statements
            # Get the base package name (before any dots)
            base_package = node.module.split(".")[0]
            self.packages.add(base_package)


def instance_to_source(instance, base_cls=None):
    cls = instance.__class__
    class_name = cls.__name__
    
    class_lines = [f"class {class_name}({base_cls.__name__}):" if base_cls else f"class {class_name}:"]
    
    if cls.__doc__ and (not base_cls or cls.__doc__ != base_cls.__doc__):
        class_lines.append(f'    """{cls.__doc__}"""')
    
    class_attrs = {
        name: value for name, value in cls.__dict__.items()
        if not name.startswith("__") and not name == "_abc_impl" and not callable(value)
        and not (base_cls and hasattr(base_cls, name) and getattr(base_cls, name) == value)
    }
    
    for name, value in class_attrs.items():
        if isinstance(value, str):
            if "\n" in value:
                escaped_value = value.replace('"""', r"\"\"\"")
                class_lines.append(f'    {name} = """{escaped_value}"""')
            else:
                class_lines.append(f"    {name} = {json.dumps(value)}")
        else:
            class_lines.append(f"    {name} = {repr(value)}")
    
    if class_attrs:
        class_lines.append("")
    
    methods = {
        name: func.__wrapped__ if hasattr(func, "__wrapped__") else func
        for name, func in cls.__dict__.items()
        if callable(func) and (not base_cls or not hasattr(base_cls, name) or 
            isinstance(func, (staticmethod, classmethod)) or 
            getattr(base_cls, name).__code__.co_code != func.__code__.co_code)
    }
    
    for name, method in methods.items():
        method_source = get_source(method)
        method_lines = method_source.split("\n")
        indent = len(method_lines[0]) - len(method_lines[0].lstrip())
        method_lines = [line[indent:] for line in method_lines]
        method_source = "\n".join(["    " + line if line.strip() else line for line in method_lines])
        class_lines.append(method_source)
        class_lines.append("")
    
    import_finder = ImportFinder()
    import_finder.visit(ast.parse("\n".join(class_lines)))
    
    final_lines = []
    if base_cls:
        final_lines.append(f"from {base_cls.__module__} import {base_cls.__name__}")
    for package in import_finder.packages:
        final_lines.append(f"import {package}")
    if final_lines:
        final_lines.append("")
    final_lines.extend(class_lines)
    
    return "\n".join(final_lines)


def get_source(obj) -> str:
    """Get the source code of a class or callable object (e.g.: function, method).
    First attempts to get the source code using `inspect.getsource`.
    In a dynamic environment (e.g.: Jupyter, IPython), if this fails,
    falls back to retrieving the source code from the current interactive shell session.

    Args:
        obj: A class or callable object (e.g.: function, method)

    Returns:
        str: The source code of the object, dedented and stripped

    Raises:
        TypeError: If object is not a class or callable
        OSError: If source code cannot be retrieved from any source
        ValueError: If source cannot be found in IPython history

    Note:
        TODO: handle Python standard REPL
    """
    if not (isinstance(obj, type) or callable(obj)):
        raise TypeError(f"Expected class or callable, got {type(obj)}")

    inspect_error = None
    try:
        # Handle dynamically created classes
        source = getattr(obj, "__source__", None) or inspect.getsource(obj)
        return dedent(source).strip()
    except OSError as e:
        # let's keep track of the exception to raise it if all further methods fail
        inspect_error = e
    try:
        import IPython

        shell = IPython.get_ipython()
        if not shell:
            raise ImportError("No active IPython shell found")
        all_cells = "\n".join(shell.user_ns.get("In", [])).strip()
        if not all_cells:
            raise ValueError("No code cells found in IPython session")

        tree = ast.parse(all_cells)
        for node in ast.walk(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name == obj.__name__:
                return dedent("\n".join(all_cells.split("\n")[node.lineno - 1 : node.end_lineno])).strip()
        raise ValueError(f"Could not find source code for {obj.__name__} in IPython history")
    except ImportError:
        # IPython is not available, let's just raise the original inspect error
        raise inspect_error
    except ValueError as e:
        # IPython is available but we couldn't find the source code, let's raise the error
        raise e from inspect_error


def encode_image_base64(image):
    buffered = BytesIO()
    image.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")


def make_image_url(base64_image):
    return f"data:image/png;base64,{base64_image}"


def make_init_file(folder: str | Path):
    os.makedirs(folder, exist_ok=True)
    # Create __init__
    with open(os.path.join(folder, "__init__.py"), "w"):
        pass


def is_valid_name(name: str) -> bool:
    return name.isidentifier() and not keyword.iskeyword(name) if isinstance(name, str) else False


AGENT_GRADIO_APP_TEMPLATE = """import yaml
import os
from smolagents import GradioUI, {{ class_name }}, {{ agent_dict['model']['class'] }}

# Get current directory path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

{% for tool in tools.values() -%}
from {{managed_agent_relative_path}}tools.{{ tool.name }} import {{ tool.__class__.__name__ }} as {{ tool.name | camelcase }}
{% endfor %}
{% for managed_agent in managed_agents.values() -%}
from {{managed_agent_relative_path}}managed_agents.{{ managed_agent.name }}.app import agent_{{ managed_agent.name }}
{% endfor %}

model = {{ agent_dict['model']['class'] }}(
{% for key in agent_dict['model']['data'] if key != 'class' -%}
    {{ key }}={{ agent_dict['model']['data'][key]|repr }},
{% endfor %})

{% for tool in tools.values() -%}
{{ tool.name }} = {{ tool.name | camelcase }}()
{% endfor %}

with open(os.path.join(CURRENT_DIR, "prompts.yaml"), 'r') as stream:
    prompt_templates = yaml.safe_load(stream)

{{ agent_name }} = {{ class_name }}(
    model=model,
    tools=[{% for tool_name in tools.keys() if tool_name != "final_answer" %}{{ tool_name }}{% if not loop.last %}, {% endif %}{% endfor %}],
    managed_agents=[{% for subagent_name in managed_agents.keys() %}agent_{{ subagent_name }}{% if not loop.last %}, {% endif %}{% endfor %}],
    {% for attribute_name, value in agent_dict.items() if attribute_name not in ["class", "model", "tools", "prompt_templates", "authorized_imports", "managed_agents", "requirements"] -%}
    {{ attribute_name }}={{ value|repr }},
    {% endfor %}prompt_templates=prompt_templates
)
if __name__ == "__main__":
    GradioUI({{ agent_name }}).launch()
""".strip()



class RateLimiter:
    """Simple rate limiter that enforces a minimum delay between consecutive requests.

    This class is useful for limiting the rate of operations such as API requests,
    by ensuring that calls to `throttle()` are spaced out by at least a given interval
    based on the desired requests per minute.

    If no rate is specified (i.e., `requests_per_minute` is None), rate limiting
    is disabled and `throttle()` becomes a no-op.

    Args:
        requests_per_minute (`float | None`): Maximum number of allowed requests per minute.
            Use `None` to disable rate limiting.
    """

    def __init__(self, requests_per_minute: float | None = None):
        self._enabled = requests_per_minute is not None
        self._interval = 60.0 / requests_per_minute if self._enabled else 0.0
        self._last_call = 0.0

    def throttle(self):
        """Pause execution to respect the rate limit, if enabled."""
        if not self._enabled:
            return
        now = time.time()
        elapsed = now - self._last_call
        if elapsed < self._interval:
            time.sleep(self._interval - elapsed)
        self._last_call = time.time()
