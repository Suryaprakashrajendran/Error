import json
from pathlib import Path


def ensure_output_dir(path: Path):
    """Ensure the output directory exists, create if not"""
    path.mkdir(parents=True, exist_ok=True)


def safe_serialize(obj):
    """Used with json.dumps to avoid errors for complex objects."""
    try:
        return str(obj)
    except Exception:
        return repr(obj)


def print_json_pretty(data, title=None):
    """Print JSON data in a pretty format to terminal"""
    if title:
        print(f"\n{'='*60}")
        print(f"{title}")
        print('='*60)
    
    try:
        json_str = json.dumps(data, indent=2, default=safe_serialize, ensure_ascii=False)
        print(json_str)
    except Exception as e:
        print(f"Error formatting JSON: {e}")
        print(str(data))
    
    if title:
        print('='*60)


def write_json_file(results: dict, filename: Path) -> Path:
    """Write results to JSON file"""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=safe_serialize, ensure_ascii=False)
    return filename


def write_html_file(html: str, filename: Path) -> Path:
    """Write HTML content to file"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename