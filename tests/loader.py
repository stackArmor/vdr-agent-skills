"""Load a skill script as a module for unit testing (scripts are not packages)."""
import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL = REPO_ROOT / "skills" / "generate-security-objectives"
SCRIPTS = SKILL / "scripts"


def load_script(stem):
    path = SCRIPTS / f"{stem}.py"
    spec = importlib.util.spec_from_file_location(stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
