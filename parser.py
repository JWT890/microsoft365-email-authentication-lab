#!/usr/bin/env python3
"""Parse DMARC aggregate (RUA) reports and summarize who sent mail as your domain.

Accepts .xml, .xml.gz and .zip files (or folders of them), as sent by Google,
Microsoft and other receivers. Works offline; no network lookups.

Usage:
    python dmarc_parser.py reports/                  # table + summary
    python dmarc_parser.py report.xml.gz --fail-only
    python dmarc_parser.py reports/ --csv out.csv

Reports come from outside parties, so the XML is untrusted. If the optional
defusedxml package is installed it is used. Otherwise files containing a DTD or
entity declaration are refused, and decompressed size is capped either way.
"""

import argparse
import csv
import gzip
import io
import sys
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from defusedxml import ElementTree as ET  # type: ignore[reportMissingImports]

    SAFE_XML = True
except ImportError:
    import xml.etree.ElementTree as ET

    SAFE_XML = False

MAX_BYTES = 20 * 1024 * 1024  # cap on decompressed size per file
EXTENSIONS = (".xml", ".gz", ".zip")


# ---------------------------------------------------------------- loading ---
def _read_limited(stream):
    data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"decompressed data exceeds {MAX_BYTES // (1024 * 1024)} MB limit")
    return data


def load_xml_documents(path):
    """Yield (label, xml_bytes) for every XML document inside a file."""
    raw = Path(path).read_bytes()
    if raw[:2] == b"\x1f\x8b":  # gzip
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            yield path.name, _read_limited(gz)
    elif raw[:4] == b"PK\x03\x04":  # zip
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for info in zf.infolist():
                if info.filename.lower().endswith(".xml") and not info.is_dir():
                    with zf.open(info) as member:
                        yield f"{path.name}:{info.filename}", _read_limited(member)
    else:
        if len(raw) > MAX_BYTES:
            raise ValueError("file exceeds size limit")
        yield path.name, raw


# ---------------------------------------------------------------- parsing ---
def _strip_namespaces(root):
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def _text(el, path, default=""):
    node = el.find(path) if el is not None else None
    return (node.text or "").strip() if node is not None else default


def _utc(epoch):
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    except (TypeError, ValueError):
        return None


def parse_report(data, label):
    if not SAFE_XML:
        upper = data.upper()
        if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
            raise ValueError("refusing XML with a DTD or entities (install defusedxml to allow)")
    root = ET.fromstring(data)
    _strip_namespaces(root)
    if root.tag != "feedback":
        raise ValueError("not a DMARC aggregate report (no <feedback> root)")

    meta = root.find("report_metadata")
    pol = root.find("policy_published")
    report = {
        "source_file": label,
        "org": _text(meta, "org_name"),
        "report_id": _text(meta, "report_id"),
        "begin": _utc(_text(meta, "date_range/begin")),
        "end": _utc(_text(meta, "date_range/end")),
        "domain": _text(pol, "domain"),
        "policy": {k: _text(pol, k) for k in ("p", "sp", "pct", "adkim", "aspf", "fo")},
        "records": [],
    }

    for rec in root.findall("record"):
        row = rec.find("row")
        evaluated = row.find("policy_evaluated") if row is not None else None
        try:
            count = int(_text(row, "count", "0"))
        except ValueError:
            count = 0
        dkim_eval = _text(evaluated, "dkim")
        spf_eval = _text(evaluated, "spf")
        dkim_auth = [
            (_text(d, "domain"), _text(d, "selector"), _text(d, "result"))
            for d in rec.findall("auth_results/dkim")
        ]
        spf_auth = [
            (_text(s, "domain"), _text(s, "result")) for s in rec.findall("auth_results/spf")
        ]
        dmarc_pass = dkim_eval == "pass" or spf_eval == "pass"
        any_auth_pass = any(r == "pass" for _, _, r in dkim_auth) or any(
            r == "pass" for _, r in spf_auth
        )
        if dmarc_pass:
            note = ""
        elif any_auth_pass:
            note = "authenticates for another domain (unaligned)"
        else:
            note = "no mechanism passed"
        report["records"].append(
            {
                "source_ip": _text(row, "source_ip"),
                "count": count,
                "disposition": _text(evaluated, "disposition"),
                "dkim_eval": dkim_eval,
                "spf_eval": spf_eval,
                "dmarc_pass": dmarc_pass,
                "override": "; ".join(
                    f"{_text(r, 'type')} {_text(r, 'comment')}".strip()
                    for r in (evaluated.findall("reason") if evaluated is not None else [])
                ),
                "header_from": _text(rec, "identifiers/header_from"),
                "envelope_from": _text(rec, "identifiers/envelope_from"),
                "dkim_auth": dkim_auth,
                "spf_auth": spf_auth,
                "note": note,
            }
        )
    return report


def collect_files(paths):
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file() and child.name.lower().endswith(EXTENSIONS):
                    yield child
        elif p.is_file():
            yield p
        else:
            print(f"warning: {p} not found", file=sys.stderr)


# --------------------------------------------------------------- reporting ---
def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M") if dt else "?"


def _auth_summary(rec):
    spf = ",".join(f"{d}={r}" for d, r in rec["spf_auth"]) or "-"
    dkim = ",".join(f"{d}={r}" for d, _, r in rec["dkim_auth"]) or "-"
    return spf, dkim


def print_report(report, fail_only):
    p = report["policy"]
    print("=" * 78)
    print(f"{report['org']}  report {report['report_id']}  ({report['source_file']})")
    print(f"Window (UTC): {_fmt(report['begin'])} to {_fmt(report['end'])}")
    print(
        f"Policy seen: domain={report['domain']} p={p['p']} sp={p['sp'] or '-'} "
        f"pct={p['pct'] or '-'} adkim={p['adkim'] or '-'} aspf={p['aspf'] or '-'}"
    )
    shown = [r for r in report["records"] if not (fail_only and r["dmarc_pass"])]
    if not shown:
        print("  (no rows to show)")
        return
    for r in shown:
        spf, dkim = _auth_summary(r)
        verdict = "PASS" if r["dmarc_pass"] else "FAIL"
        print(
            f"  {r['source_ip']:<40} n={r['count']:<4} DMARC {verdict}  "
            f"disp={r['disposition'] or '-'}  spf_aligned={r['spf_eval'] or '-'} "
            f"dkim_aligned={r['dkim_eval'] or '-'}"
        )
        print(f"      from={r['header_from']}  spf[{spf}]  dkim[{dkim}]")
        if r["note"]:
            print(f"      note: {r['note']}")
        if r["override"]:
            print(f"      override: {r['override']}")


def print_summary(reports):
    total = passed = 0
    by_ip = defaultdict(lambda: {"count": 0, "pass": 0, "disp": set()})
    for rep in reports:
        for r in rep["records"]:
            total += r["count"]
            ip = by_ip[r["source_ip"]]
            ip["count"] += r["count"]
            ip["disp"].add(r["disposition"] or "-")
            if r["dmarc_pass"]:
                passed += r["count"]
                ip["pass"] += r["count"]
    print("=" * 78)
    print(f"SUMMARY: {len(reports)} report(s), {total} message(s)")
    if total:
        print(f"  DMARC pass: {passed} ({passed * 100 // total}%)   fail: {total - passed}")
    print("  By source IP:")
    for ip, s in sorted(by_ip.items(), key=lambda kv: -kv[1]["count"]):
        status = "all pass" if s["pass"] == s["count"] else (
            "all fail" if s["pass"] == 0 else "mixed"
        )
        print(f"    {ip:<40} {s['count']:>5} msgs  {status:<9} disp={','.join(sorted(s['disp']))}")


def write_csv(reports, out_path):
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "reporter", "report_id", "begin_utc", "end_utc", "domain", "policy_p",
                "source_ip", "count", "disposition", "dkim_aligned", "spf_aligned",
                "dmarc_pass", "header_from", "spf_auth", "dkim_auth", "note",
            ]
        )
        for rep in reports:
            for r in rep["records"]:
                spf, dkim = _auth_summary(r)
                w.writerow(
                    [
                        rep["org"], rep["report_id"], _fmt(rep["begin"]), _fmt(rep["end"]),
                        rep["domain"], rep["policy"]["p"], r["source_ip"], r["count"],
                        r["disposition"], r["dkim_eval"], r["spf_eval"], r["dmarc_pass"],
                        r["header_from"], spf, dkim, r["note"],
                    ]
                )


# -------------------------------------------------------------------- main ---
def main(argv=None):
    ap = argparse.ArgumentParser(description="Summarize DMARC aggregate reports.")
    ap.add_argument("paths", nargs="+", help="report files or folders")
    ap.add_argument("--fail-only", action="store_true", help="show only DMARC-failing rows")
    ap.add_argument("--csv", metavar="FILE", help="also write all rows to a CSV file")
    args = ap.parse_args(argv)

    if not SAFE_XML:
        print("note: defusedxml not installed; DTD/entity XML will be refused.", file=sys.stderr)

    reports = []
    for path in collect_files(args.paths):
        try:
            for label, data in load_xml_documents(path):
                reports.append(parse_report(data, label))
        except Exception as exc:  # keep going; one bad file should not stop the rest
            print(f"skipped {path.name}: {exc}", file=sys.stderr)

    if not reports:
        print("No reports parsed.", file=sys.stderr)
        return 1

    reports.sort(key=lambda r: (r["begin"] or datetime.min.replace(tzinfo=timezone.utc)))
    for rep in reports:
        print_report(rep, args.fail_only)
    print_summary(reports)
    if args.csv:
        write_csv(reports, args.csv)
        print(f"\nWrote {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())