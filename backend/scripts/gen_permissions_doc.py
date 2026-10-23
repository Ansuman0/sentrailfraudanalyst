"""Write docs/permissions.md from the permission catalogue (app/access/catalogue.py).
Usage (from backend/): python -m scripts.gen_permissions_doc"""
from pathlib import Path
from app.access import catalogue

target = Path(__file__).resolve().parents[2] / "docs" / "permissions.md"
with open(target, "w", encoding="utf-8", newline="\n") as f:
    f.write(catalogue.render_markdown())
print(f"wrote {target}")
