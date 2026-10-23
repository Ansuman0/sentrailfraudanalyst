"""Check an audit export you received from Sentrail, without any Sentrail key: that every event's hash is right and that the events
follow each other without a gap or an edit.

  python scripts/verify_audit_export.py audit-20261023T101500Z.json

The JSON file holds, for each event, its content, the hash of the event before it (prev_hash) and its own hash. An event's hash is
SHA-256(prev_hash || canonical JSON of the event), so changing, removing or reordering any event breaks every hash after it.
Exit status 0 = intact, 1 = something does not match. (The file's HMAC signature can only be checked by Sentrail: send the file to your
Sentrail contact if you need that proof as well.)
"""
import hashlib
import json
import sys


def canonical(e: dict) -> bytes:
    return json.dumps({"org": e["org"], "at": e["at"], "actor": e["actor"], "role": e["role"], "action": e["action"], "target": e["target"],
                       "detail": e["detail"], "ip": e["ip"]}, sort_keys=True, separators=(",", ":"), default=str).encode()


def check(doc: dict) -> list[str]:
    problems, previous = [], None
    for e in doc["events"]:
        if previous is not None and e["prev_hash"] != previous["hash"]:
            problems.append(f'event {e["seq"]}: does not follow event {previous["seq"]} (an event is missing or changed)')
        if hashlib.sha256(bytes.fromhex(e["prev_hash"]) + canonical(e)).hexdigest() != e["hash"]:
            problems.append(f'event {e["seq"]}: its content does not match its hash')
        previous = e
    return problems


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(sys.argv[1], encoding="utf-8") as f:
        document = json.load(f)
    found = check(document)
    chain = document.get("chain", {})
    print(f'{len(document["events"])} events; Sentrail reported the full chain as {"verified" if chain.get("verified") else "NOT verified"}')
    for p in found:
        print("PROBLEM:", p)
    print("INTACT" if not found else f"{len(found)} problem(s)")
    sys.exit(1 if found else 0)
