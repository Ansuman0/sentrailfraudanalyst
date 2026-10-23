"""Run the background jobs (dormant sweep, access reviews, audit streaming, tenant data removal ...).

  python -m scripts.run_jobs                 run every job once and print what happened
  python -m scripts.run_jobs --only dormant_sweep audit_stream
  python -m scripts.run_jobs --loop [--every 300]   keep running (the worker container does this)
Needs DATABASE_URL and the key variables, like the API.
"""
import argparse
import json
import logging

from dotenv import load_dotenv

load_dotenv()
from app import jobs                                                    # noqa: E402
from app.logging_config import configure_logging as configure          # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--only", nargs="*", help="job names to run")
ap.add_argument("--loop", action="store_true")
ap.add_argument("--every", type=int, default=300, help="seconds between rounds with --loop")
args = ap.parse_args()
configure()
if args.loop:
    jobs.loop(args.every)
else:
    print(json.dumps(jobs.run_once(set(args.only) if args.only else None), indent=1, default=str))
