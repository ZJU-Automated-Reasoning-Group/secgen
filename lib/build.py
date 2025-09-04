import os
from tree_sitter import Language, Parser
from pathlib import Path

cwd = Path(__file__).resolve().parent.absolute()

# Clone tree-sitter language repositories if necessary
languages = {
    "tree-sitter-c": "https://github.com/tree-sitter/tree-sitter-c.git",
   # "tree-sitter-python": "https://github.com/tree-sitter/tree-sitter-python.git",
}

for lang_name, repo_url in languages.items():
    lang_path = cwd / "vendor" / lang_name
    if not (lang_path / "grammar.js").exists():
        print(f"Cloning {lang_name}...")
        os.system(f'git clone {repo_url} {lang_path}')

# Build the language library
print("Building tree-sitter language bindings...")
Language.build_library(
    # Store the library in the `build` directory
    str(cwd / "build/my-languages.so"),
    
    # Include the languages we need
    [
        str(cwd / "vendor/tree-sitter-c"),
       # str(cwd / "vendor/tree-sitter-python"),
    ],
)

print("Tree-sitter language bindings built successfully!")
