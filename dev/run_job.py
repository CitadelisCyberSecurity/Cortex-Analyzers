#!/usr/bin/env python3
"""Run one analyzer job on the dev Cortex and print the report.

    python dev/run_job.py ProxyCheck_1_0 ip 1.1.1.1
    python dev/run_job.py ProxyCheck_1_0 domain example.com --full

Logs in as the org admin that dev/bootstrap.py creates. Prints the summary
taxonomies and artifacts (what Shuffle sees), or the full report with --full.
"""

import argparse
import json
import sys

from bootstrap import ORG_ADMIN, Cortex


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("analyzer", help="analyzer definition id, e.g. ProxyCheck_1_0")
    parser.add_argument("data_type", help="observable type, e.g. ip, domain, url")
    parser.add_argument("data", help="observable value")
    parser.add_argument("--tlp", type=int, default=2)
    parser.add_argument("--full", action="store_true", help="print the full report")
    parser.add_argument("--url", default="http://127.0.0.1:9001")
    args = parser.parse_args()

    cortex = Cortex(args.url)
    cortex.call("POST", "/api/login", {"user": ORG_ADMIN[0], "password": ORG_ADMIN[1]})
    cortex.call("GET", "/api/user/current")

    _, analyzers = cortex.call("GET", "/api/analyzer?range=all")
    matches = [a for a in analyzers if args.analyzer in (a["id"], a["name"], a.get("analyzerDefinitionId"))]
    if not matches:
        sys.exit(f"Analyzer {args.analyzer} is not enabled. Enabled: {sorted(a['name'] for a in analyzers)}")

    _, job = cortex.call(
        "POST",
        # force=1 skips the job cache, so a rebuilt image always runs.
        f"/api/analyzer/{matches[0]['id']}/run?force=1",
        {"data": args.data, "dataType": args.data_type, "tlp": args.tlp, "message": "dev/run_job.py"},
    )
    print(f"Job {job['id']} started", file=sys.stderr)
    _, report = cortex.call("GET", f"/api/job/{job['id']}/waitreport?atMost=5minutes")

    if report.get("status") != "Success":
        print(json.dumps({"status": report.get("status"), "errorMessage": report.get("errorMessage")}, indent=2))
        sys.exit(1)
    result = report["report"]
    if not args.full:
        result = {"summary": result.get("summary"), "artifacts": result.get("artifacts")}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
