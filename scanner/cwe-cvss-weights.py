#!/usr/bin/env python3
import argparse
import json
import os
import statistics
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def severity_from_score(score):
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def load_scenario_cwes(project_dir):
    scenario_root = Path(project_dir) / "scenarios"
    cwes = set()
    for metadata_path in scenario_root.rglob("metadata.json"):
        with metadata_path.open("r", encoding="utf-8") as handle:
            metadata = json.load(handle)
        if metadata.get("cwe"):
            cwes.add(metadata["cwe"])
    return sorted(cwes)


def extract_cvss_scores(payload):
    scores = []
    for item in payload.get("vulnerabilities", []):
        metrics = item.get("cve", {}).get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for metric in metrics.get(key, []):
                data = metric.get("cvssData", {})
                score = data.get("baseScore")
                if isinstance(score, (int, float)):
                    scores.append(float(score))
    return scores


def query_nvd(cwe, timeout, start_index, results_per_page):
    query = urllib.parse.urlencode({
        "cweId": cwe,
        "resultsPerPage": results_per_page,
        "startIndex": start_index
    })
    request = urllib.request.Request(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}",
        headers={"User-Agent": "CICDSecurityLab/1.0"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_nvd_scores(cwe, timeout, max_cves):
    scores = []
    total_results = None
    fetched_cves = 0
    start_index = 0
    results_per_page = min(2000, max(1, max_cves))

    while fetched_cves < max_cves:
        payload = query_nvd(cwe, timeout, start_index, results_per_page)
        vulnerabilities = payload.get("vulnerabilities", [])
        if total_results is None:
            total_results = int(payload.get("totalResults") or 0)
        scores.extend(extract_cvss_scores(payload))
        fetched_cves += len(vulnerabilities)
        start_index += int(payload.get("resultsPerPage") or len(vulnerabilities) or results_per_page)
        if not vulnerabilities or start_index >= total_results or fetched_cves >= max_cves:
            break
        time.sleep(0.7)

    return scores, total_results or 0, min(fetched_cves, total_results or fetched_cves)


def nvd_entry(cwe, timeout, max_cves):
    scores, total_results, fetched_cves = fetch_nvd_scores(cwe, timeout, max_cves)
    if not scores:
        return unavailable_entry(
            cwe,
            "NVD returned no CVSS base scores for this CWE in the fetched CVE records.",
            total_results=total_results,
            fetched_cves=fetched_cves
        )
    avg = round(sum(scores) / len(scores), 1)
    complete = fetched_cves >= total_results
    return {
        "cwe": cwe,
        "baseScore": avg,
        "severity": severity_from_score(avg),
        "confidence": "NVD_AVERAGE_ALL_MATCHING_CVES" if complete else "NVD_AVERAGE_PARTIAL_CVES",
        "sampleSize": len(scores),
        "totalMatchingCves": total_results,
        "fetchedCves": fetched_cves,
        "complete": complete,
        "scoreMin": min(scores),
        "scoreMax": max(scores),
        "scoreMedian": round(statistics.median(scores), 1),
        "source": "NVD CVE API grouped by CWE",
        "rationale": "Representative score calculated from CVSS base scores in NVD CVEs mapped to this CWE."
    }


def unavailable_entry(cwe, reason, total_results=0, fetched_cves=0):
    return {
        "cwe": cwe,
        "baseScore": None,
        "severity": "UNKNOWN",
        "confidence": "UNAVAILABLE",
        "sampleSize": 0,
        "totalMatchingCves": total_results,
        "fetchedCves": fetched_cves,
        "complete": fetched_cves >= total_results if total_results else False,
        "scoreMin": None,
        "scoreMax": None,
        "scoreMedian": None,
        "source": "NVD CVE API grouped by CWE",
        "rationale": reason
    }


def main():
    parser = argparse.ArgumentParser(description="Generate representative CVSS weights for project CWEs.")
    parser.add_argument("--project-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--fetch", default=os.environ.get("CWE_CVSS_FETCH", "auto"))
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("CWE_CVSS_TIMEOUT", "2.5")))
    parser.add_argument("--max-cves-per-cwe", type=int, default=int(os.environ.get("CWE_CVSS_MAX_CVES_PER_CWE", "2000")))
    args = parser.parse_args()

    cwes = load_scenario_cwes(args.project_dir)
    entries = []
    fetch_enabled = args.fetch.lower() not in {"0", "false", "no", "off"}

    for cwe in cwes:
        if fetch_enabled:
            try:
                entry = nvd_entry(cwe, args.timeout, args.max_cves_per_cwe)
                time.sleep(0.7)
            except Exception as error:
                entry = unavailable_entry(cwe, f"NVD lookup failed: {error}")
        else:
            entry = unavailable_entry(cwe, "NVD lookup disabled by CWE_CVSS_FETCH.")
        entries.append(entry)

    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = {
        "generatedAt": generated_at,
        "validForDays": 30,
        "cwes": cwes,
        "notes": [
            "CVSS is defined for concrete vulnerabilities, not CWE classes.",
            "This table derives representative CWE severity weights from NVD CVEs mapped to each CWE.",
            "No local fallback CVSS values are used; missing lookup data is marked UNKNOWN.",
            "If totalMatchingCves is larger than fetchedCves, the entry is based on a capped partial NVD sample.",
            "Scenario coverage is still calculated from mapped scanner detections."
        ],
        "entries": entries
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote CWE CVSS table for {len(cwes)} CWEs to {output}")


if __name__ == "__main__":
    sys.exit(main())
