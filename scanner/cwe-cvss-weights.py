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


FALLBACK = {
    "CWE-16": {
        "baseScore": 6.5,
        "severity": "MEDIUM",
        "confidence": "FALLBACK",
        "rationale": "Configuration weaknesses vary widely; medium is used as a conservative representative weight."
    },
    "CWE-78": {
        "baseScore": 9.1,
        "severity": "CRITICAL",
        "confidence": "FALLBACK",
        "rationale": "Command injection commonly enables direct command execution in a trusted context."
    },
    "CWE-269": {
        "baseScore": 8.8,
        "severity": "HIGH",
        "confidence": "FALLBACK",
        "rationale": "Privilege management failures can give attackers excessive access after compromise."
    },
    "CWE-345": {
        "baseScore": 7.4,
        "severity": "HIGH",
        "confidence": "FALLBACK",
        "rationale": "Authenticity failures can allow untrusted artifacts or images to be accepted."
    },
    "CWE-494": {
        "baseScore": 8.1,
        "severity": "HIGH",
        "confidence": "FALLBACK",
        "rationale": "Executing downloaded code without integrity verification can lead to trusted code execution."
    },
    "CWE-532": {
        "baseScore": 5.3,
        "severity": "MEDIUM",
        "confidence": "FALLBACK",
        "rationale": "Log disclosure depends on log exposure, but can reveal sensitive CI/CD values."
    },
    "CWE-798": {
        "baseScore": 7.5,
        "severity": "HIGH",
        "confidence": "FALLBACK",
        "rationale": "Hardcoded credentials can enable unauthorized access if exposed."
    },
    "CWE-829": {
        "baseScore": 8.0,
        "severity": "HIGH",
        "confidence": "FALLBACK",
        "rationale": "Untrusted dependency resolution can introduce attacker-controlled functionality."
    }
}


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


def query_nvd(cwe, timeout):
    query = urllib.parse.urlencode({"cweId": cwe, "resultsPerPage": 100})
    request = urllib.request.Request(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}",
        headers={"User-Agent": "CICDSecurityLab/1.0"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def nvd_entry(cwe, timeout):
    payload = query_nvd(cwe, timeout)
    scores = extract_cvss_scores(payload)
    if not scores:
        return None
    avg = round(sum(scores) / len(scores), 1)
    return {
        "cwe": cwe,
        "baseScore": avg,
        "severity": severity_from_score(avg),
        "confidence": "NVD_AVERAGE",
        "sampleSize": len(scores),
        "scoreMin": min(scores),
        "scoreMax": max(scores),
        "scoreMedian": round(statistics.median(scores), 1),
        "source": "NVD CVE API grouped by CWE",
        "rationale": "Representative score calculated from available CVE CVSS base scores for this CWE."
    }


def fallback_entry(cwe):
    data = FALLBACK.get(cwe, {
        "baseScore": 0,
        "severity": "UNKNOWN",
        "confidence": "UNKNOWN",
        "rationale": "No local fallback score is available for this CWE."
    })
    return {
        "cwe": cwe,
        "baseScore": data["baseScore"],
        "severity": data["severity"],
        "confidence": data["confidence"],
        "sampleSize": 0,
        "scoreMin": data["baseScore"],
        "scoreMax": data["baseScore"],
        "scoreMedian": data["baseScore"],
        "source": "Local representative CWE severity fallback",
        "rationale": data["rationale"]
    }


def main():
    parser = argparse.ArgumentParser(description="Generate representative CVSS weights for project CWEs.")
    parser.add_argument("--project-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--fetch", default=os.environ.get("CWE_CVSS_FETCH", "auto"))
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("CWE_CVSS_TIMEOUT", "2.5")))
    args = parser.parse_args()

    cwes = load_scenario_cwes(args.project_dir)
    entries = []
    fetch_enabled = args.fetch.lower() not in {"0", "false", "no", "off"}
    nvd_disabled_after_error = False

    for cwe in cwes:
        entry = None
        if fetch_enabled and not nvd_disabled_after_error:
            try:
                entry = nvd_entry(cwe, args.timeout)
                time.sleep(0.7)
            except Exception as error:
                nvd_disabled_after_error = True
                entry = None
        entries.append(entry or fallback_entry(cwe))

    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = {
        "generatedAt": generated_at,
        "validForDays": 30,
        "cwes": cwes,
        "notes": [
            "CVSS is defined for concrete vulnerabilities, not CWE classes.",
            "This table provides representative CWE severity weights for lab analysis.",
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
