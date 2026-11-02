#!/usr/bin/env python3
"""
Trivy Vulnerability Deduplication Script
-----------------------------------------
Processes Trivy JSON scan outputs for the OSC Near-RT RIC images.
Produces a deduplicated summary of unique CVE+package combinations
at HIGH and CRITICAL severity, with per-image breakdowns and
image-level instance counts.

Usage:
    python3 trivy-dedup-analysis.py <scan_directory> [output_file]

Arguments:
    scan_directory  Directory containing ric-plt-*.json Trivy scan files
    output_file     Optional output path (default: prints to stdout)
"""

import json
import os
import sys
import glob


def process_scans(scan_dir):
    all_cves = {}
    per_image = {}
    json_files = sorted(glob.glob(os.path.join(scan_dir, "ric-plt-*.json")))

    if not json_files:
        print(f"No ric-plt-*.json files found in {scan_dir}", file=sys.stderr)
        sys.exit(1)

    for jf in json_files:
        img = os.path.basename(jf).replace(".json", "")
        with open(jf, "r", encoding="utf-8") as f:
            data = json.load(f)

        img_cves = set()
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities") or []:
                sev = vuln.get("Severity", "UNKNOWN").upper()
                if sev not in {"HIGH", "CRITICAL"}:
                    continue
                cve_id = vuln.get("VulnerabilityID", "unknown")
                pkg = vuln.get("PkgName", "unknown")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                title = vuln.get("Title", "")
                key = (cve_id, pkg)
                img_cves.add(key)
                if key not in all_cves:
                    all_cves[key] = {
                        "id": cve_id, "pkg": pkg, "sev": sev,
                        "title": title, "images": {}
                    }
                all_cves[key]["images"][img] = {
                    "installed": installed, "fixed": fixed
                }

        crit = sum(1 for k in img_cves if all_cves[k]["sev"] == "CRITICAL")
        high = sum(1 for k in img_cves if all_cves[k]["sev"] == "HIGH")
        per_image[img] = {"CRITICAL": crit, "HIGH": high, "TOTAL": crit + high}

    return all_cves, per_image, len(json_files)


def validate(all_cves, per_image):
    total_instances = sum(len(v["images"]) for v in all_cves.values())
    per_image_total = sum(d["TOTAL"] for d in per_image.values())
    if total_instances != per_image_total:
        raise RuntimeError(
            f"Instance-count mismatch: deployment={total_instances}, "
            f"per-image sum={per_image_total}"
        )
    return total_instances


def format_report(all_cves, per_image, num_images, total_instances):
    unique = len(all_cves)
    crit_unique = sum(1 for v in all_cves.values() if v["sev"] == "CRITICAL")
    high_unique = sum(1 for v in all_cves.values() if v["sev"] == "HIGH")
    crit_inst = sum(len(v["images"]) for v in all_cves.values() if v["sev"] == "CRITICAL")
    high_inst = sum(len(v["images"]) for v in all_cves.values() if v["sev"] == "HIGH")

    lines = []
    lines.append("=" * 70)
    lines.append("TRIVY DEDUPLICATED VULNERABILITY SUMMARY")
    lines.append("=" * 70)
    lines.append(f"Images processed: {num_images}")
    lines.append(f"TOTAL IMAGE-LEVEL CVE+PACKAGE INSTANCES: {total_instances}")
    lines.append(f"UNIQUE CVE+PACKAGE COMBINATIONS: {unique}")
    lines.append(f"  CRITICAL: {crit_unique} unique ({crit_inst} image-level instances)")
    lines.append(f"  HIGH: {high_unique} unique ({high_inst} image-level instances)")
    lines.append("=" * 70)
    lines.append("")
    lines.append("PER-IMAGE UNIQUE HIGH/CRITICAL COUNTS:")
    lines.append("")
    for img in sorted(per_image):
        d = per_image[img]
        lines.append(f"  {img}: CRITICAL={d['CRITICAL']} HIGH={d['HIGH']} TOTAL={d['TOTAL']}")
    lines.append("")
    lines.append("=" * 70)
    lines.append("ALL UNIQUE CRITICAL CVE+PACKAGE COMBINATIONS")
    lines.append("=" * 70)
    for key, v in sorted(all_cves.items(), key=lambda x: (x[1]["id"], x[1]["pkg"])):
        if v["sev"] != "CRITICAL":
            continue
        lines.append(f"{v['id']} | Package: {v['pkg']}")
        lines.append(f"  Title: {v['title']}")
        lines.append(f"  Affected images ({len(v['images'])}):")
        for img in sorted(v["images"]):
            d = v["images"][img]
            lines.append(f"    {img} | Installed: {d['installed']} | Fixed: {d['fixed']}")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    scan_dir = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    all_cves, per_image, num_images = process_scans(scan_dir)
    total_instances = validate(all_cves, per_image)
    report = format_report(all_cves, per_image, num_images, total_instances)
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Report saved to: {output_file}")
    else:
        print(report)
