#!/usr/bin/env python3
"""Script to create necessary __init__.py files"""

import os
from pathlib import Path

def create_init_files():
    # Get project root directory
    project_root = Path.cwd()
    
    # Directories that need __init__.py files
    dirs_need_init = [
        "src",
        "src/kems",
        "src/signatures",
        "src/utils",
        "src/config",
        "src/baseline",
        "tests"
    ]
    
    # Create __init__.py files
    for dir_path in dirs_need_init:
        init_path = project_root / dir_path / "__init__.py"
        init_path.parent.mkdir(parents=True, exist_ok=True)
        
        if not init_path.exists():
            init_path.touch()
            print(f"Created {init_path}")
        else:
            print(f"File already exists: {init_path}")

if __name__ == "__main__":
    create_init_files()