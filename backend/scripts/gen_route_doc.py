"""Write docs/route-permissions.md from the app's routes. Usage (from backend/): python -m scripts.gen_route_doc"""
from pathlib import Path
from app.access import routes
from app.main import app

target = Path(__file__).resolve().parents[2] / "docs" / "route-permissions.md"
with open(target, "w", encoding="utf-8", newline="\n") as f:
    f.write(routes.render_markdown(app))
print(f"wrote {target}")
