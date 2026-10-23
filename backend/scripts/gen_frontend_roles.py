"""Write frontend/src/test/roles.fixture.json from the role templates (app/access/catalogue.py): the permissions each built-in role holds, used
by the web app's per-role tests. Usage (from backend/): python -m scripts.gen_frontend_roles"""
import json
from pathlib import Path

from app.access import catalogue

target = Path(__file__).resolve().parents[2] / "frontend" / "src" / "test" / "roles.fixture.json"


def render() -> str:
    roles = {t.name: {"scope": t.scope, "permissions": sorted(t.perms)} for t in catalogue.TEMPLATES}
    return json.dumps(roles, indent=2) + "\n"


if __name__ == "__main__":
    with open(target, "w", encoding="utf-8", newline="\n") as f:
        f.write(render())
    print(f"wrote {target}")
