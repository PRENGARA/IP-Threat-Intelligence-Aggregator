#!/usr/bin/env python3

"""

ioc_lookup.py — IP Address Threat Intelligence Aggregator

============================================================



Takes an IP address as input and returns:

  - An aggregated severity/risk verdict (Clean / Low / Medium / High / Critical)

  - Per-source reputation data (AbuseIPDB, VirusTotal, AlienVault OTX)

  - Related Indicators of Compromise (IOCs): malicious file hashes and

    domains that have been seen communicating with / resolving to the IP



This tool is a THIN AGGREGATOR over public, reputable threat-intel APIs.

It does not scan, exploit, or attack anything — it only reads published

reputation data about an IP that you provide. Intended for SOC analysts,

incident responders, and defenders doing IOC triage.



------------------------------------------------------------------------

SETUP

------------------------------------------------------------------------

1. Install dependencies:

     pip install requests --break-system-packages



2. Get free API keys (all have free tiers):

     - AbuseIPDB : https://www.abuseipdb.com/account/api

     - VirusTotal: https://www.virustotal.com/gui/my-apikey

     - OTX       : https://otx.alienvault.com/api



3. Export them as environment variables:

     export ABUSEIPDB_API_KEY="your_key_here"

     export VT_API_KEY="your_key_here"

     export OTX_API_KEY="your_key_here"



   (You don't need all three — the tool will run with whichever keys

   are present and skip sources that aren't configured.)



------------------------------------------------------------------------

USAGE

------------------------------------------------------------------------

    python3 ioc_lookup.py 8.8.8.8

    python3 ioc_lookup.py 8.8.8.8 --json

    python3 ioc_lookup.py 8.8.8.8 --json --out result.json

    python3 ioc_lookup.py --batch ips.txt



------------------------------------------------------------------------

"""



import os

import sys

import json

import time

import ipaddress

import argparse

from datetime import datetime, timezone



try:

    import requests

except ImportError:

    print("Missing dependency 'requests'. Install with:")

    print("  pip install requests --break-system-packages")

    sys.exit(1)





# ----------------------------------------------------------------------

# Config

# ----------------------------------------------------------------------



ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

VT_API_KEY = os.environ.get("VT_API_KEY", "")

OTX_API_KEY = os.environ.get("OTX_API_KEY", "")



REQUEST_TIMEOUT = 30  # seconds

MAX_RELATED_IOCS = 25  # cap how many hashes/domains we print per source





# ----------------------------------------------------------------------

# Helpers

# ----------------------------------------------------------------------



def validate_ip(ip_str):

    try:

        ipaddress.ip_address(ip_str)

        return True

    except ValueError:

        return False





def safe_get(url, headers=None, params=None):

    """GET with basic error handling; never raises, returns (ok, data/err)."""

    try:

        resp = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 200:

            return True, resp.json()

        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"

    except requests.exceptions.RequestException as e:

        return False, str(e)





# ----------------------------------------------------------------------

# Source: AbuseIPDB

# ----------------------------------------------------------------------



def query_abuseipdb(ip):

    result = {"source": "AbuseIPDB", "configured": bool(ABUSEIPDB_API_KEY), "ok": False}

    if not ABUSEIPDB_API_KEY:

        result["note"] = "ABUSEIPDB_API_KEY not set — skipped"

        return result



    ok, data = safe_get(

        "https://api.abuseipdb.com/api/v2/check",

        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},

        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},

    )

    if not ok:

        result["error"] = data

        return result



    d = data.get("data", {})

    result.update({

        "ok": True,

        "abuse_confidence_score": d.get("abuseConfidenceScore"),  # 0-100

        "total_reports": d.get("totalReports"),

        "distinct_reporters": d.get("numDistinctUsers"),

        "country": d.get("countryCode"),

        "isp": d.get("isp"),

        "usage_type": d.get("usageType"),

        "domain": d.get("domain"),

        "is_tor": d.get("isTor"),

        "last_reported_at": d.get("lastReportedAt"),

    })

    return result





# ----------------------------------------------------------------------

# Source: VirusTotal

# ----------------------------------------------------------------------



def query_virustotal(ip):

    result = {"source": "VirusTotal", "configured": bool(VT_API_KEY), "ok": False}

    if not VT_API_KEY:

        result["note"] = "VT_API_KEY not set — skipped"

        return result



    headers = {"x-apikey": VT_API_KEY}



    # 1. Base IP reputation

    ok, data = safe_get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)

    if not ok:

        result["error"] = data

        return result



    attrs = data.get("data", {}).get("attributes", {})

    stats = attrs.get("last_analysis_stats", {})

    result.update({

        "ok": True,

        "malicious_votes": stats.get("malicious", 0),

        "suspicious_votes": stats.get("suspicious", 0),

        "harmless_votes": stats.get("harmless", 0),

        "undetected_votes": stats.get("undetected", 0),

        "reputation_score": attrs.get("reputation"),

        "as_owner": attrs.get("as_owner"),

        "country": attrs.get("country"),

        "tags": attrs.get("tags", []),

    })



    # 2. Related malicious files (hashes) that communicate with this IP

    ok2, files_data = safe_get(

        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/communicating_files",

        headers=headers, params={"limit": MAX_RELATED_IOCS},

    )

    hashes = []

    if ok2:

        for item in files_data.get("data", []):

            a = item.get("attributes", {})

            fstats = a.get("last_analysis_stats", {})

            if fstats.get("malicious", 0) > 0:  # only surface flagged files

                hashes.append({

                    "sha256": a.get("sha256"),

                    "type": a.get("type_description"),

                    "malicious_detections": fstats.get("malicious"),

                    "meaningful_name": a.get("meaningful_name"),

                })

    result["related_hashes"] = hashes



    # 3. Related domains resolving to this IP

    ok3, res_data = safe_get(

        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions",

        headers=headers, params={"limit": MAX_RELATED_IOCS},

    )

    domains = []

    if ok3:

        for item in res_data.get("data", []):

            a = item.get("attributes", {})

            domains.append({

                "domain": a.get("host_name"),

                "date": a.get("date"),

            })

    result["related_domains"] = domains



    return result





# ----------------------------------------------------------------------

# Source: AlienVault OTX

# ----------------------------------------------------------------------



def query_otx(ip):

    result = {"source": "AlienVault OTX", "configured": bool(OTX_API_KEY), "ok": False}

    if not OTX_API_KEY:

        result["note"] = "OTX_API_KEY not set — skipped"

        return result



    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    ok, data = safe_get(

        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",

        headers=headers,

    )

    if not ok:

        result["error"] = data

        return result



    pulse_info = data.get("pulse_info", {})

    result.update({

        "ok": True,

        "pulse_count": pulse_info.get("count", 0),

        "pulse_names": [p.get("name") for p in pulse_info.get("pulses", [])[:MAX_RELATED_IOCS]],

        "asn": data.get("asn"),

        "country_name": data.get("country_name"),

    })



    # Related malware hashes seen associated with this indicator

    ok2, mal_data = safe_get(

        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/malware",

        headers=headers,

    )

    hashes = []

    if ok2:

        for item in mal_data.get("data", [])[:MAX_RELATED_IOCS]:

            hashes.append({

                "hash": item.get("hash"),

                "detections": item.get("detections"),

            })

    result["related_hashes"] = hashes



    # Passive DNS -> related domains

    ok3, pdns_data = safe_get(

        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns",

        headers=headers,

    )

    domains = []

    if ok3:

        for item in pdns_data.get("passive_dns", [])[:MAX_RELATED_IOCS]:

            domains.append({

                "domain": item.get("hostname"),

                "first_seen": item.get("first"),

                "last_seen": item.get("last"),

            })

    result["related_domains"] = domains



    return result





# ----------------------------------------------------------------------

# Aggregation / Severity Scoring

# ----------------------------------------------------------------------



def compute_severity(abuse, vt, otx):

    """

    Combine signals from all sources into one 0-100 risk score and a

    human-readable severity band. Weights are heuristic, not authoritative —

    tune to your environment.

    """

    score = 0

    reasons = []



    if abuse.get("ok"):

        conf = abuse.get("abuse_confidence_score") or 0

        score += conf * 0.4

        if conf > 0:

            reasons.append(f"AbuseIPDB confidence score: {conf}/100")

        if abuse.get("is_tor"):

            score += 10

            reasons.append("Exit node on the Tor network")



    if vt.get("ok"):

        mal = vt.get("malicious_votes") or 0

        susp = vt.get("suspicious_votes") or 0

        vt_component = min(mal * 8 + susp * 3, 40)

        score += vt_component

        if mal or susp:

            reasons.append(f"VirusTotal: {mal} malicious / {susp} suspicious vendor flags")



        related_hashes = vt.get("related_hashes") or []

        if related_hashes:

            # Weight by how many communicating files are flagged AND how badly

            # (average detections across those files), capped so one source

            # can't single-handedly max the score.

            avg_detections = sum(h.get("malicious_detections", 0) or 0 for h in related_hashes) / len(related_hashes)

            hash_component = min(len(related_hashes) * 2 + avg_detections * 0.3, 45)

            score += hash_component

            reasons.append(

                f"VirusTotal: {len(related_hashes)} malicious file(s) communicating with this IP "

                f"(avg {avg_detections:.0f} vendor detections)"

            )



    if otx.get("ok"):

        pulses = otx.get("pulse_count") or 0

        otx_component = min(pulses * 4, 20)

        score += otx_component

        if pulses:

            reasons.append(f"OTX: referenced in {pulses} threat intel pulse(s)")



    score = min(round(score), 100)



    if score == 0:

        band = "Clean / No Signal"

    elif score < 20:

        band = "Low"

    elif score < 50:

        band = "Medium"

    elif score < 80:

        band = "High"

    else:

        band = "Critical"



    return score, band, reasons





# ----------------------------------------------------------------------

# Main lookup orchestration

# ----------------------------------------------------------------------



def lookup_ip(ip):

    if not validate_ip(ip):

        return {"ip": ip, "error": "Invalid IP address format"}



    abuse = query_abuseipdb(ip)

    time.sleep(0.2)

    vt = query_virustotal(ip)

    time.sleep(0.2)

    otx = query_otx(ip)



    score, band, reasons = compute_severity(abuse, vt, otx)



    all_hashes = []

    all_domains = []

    for src in (vt, otx):

        for h in src.get("related_hashes", []) or []:

            h2 = dict(h)

            h2["source"] = src["source"]

            all_hashes.append(h2)

        for d in src.get("related_domains", []) or []:

            d2 = dict(d)

            d2["source"] = src["source"]

            all_domains.append(d2)



    return {

        "ip": ip,

        "queried_at_utc": datetime.now(timezone.utc).isoformat(),

        "severity": {

            "score": score,

            "band": band,

            "reasons": reasons,

        },

        "sources": {

            "abuseipdb": abuse,

            "virustotal": vt,

            "otx": otx,

        },

        "related_iocs": {

            "hashes": all_hashes,

            "domains": all_domains,

        },

    }





# ----------------------------------------------------------------------

# Output formatting

# ----------------------------------------------------------------------



SEVERITY_COLOR = {

    "Clean / No Signal": "\033[92m",  # green

    "Low": "\033[92m",

    "Medium": "\033[93m",  # yellow

    "High": "\033[91m",    # red

    "Critical": "\033[95m",  # magenta

}

RESET = "\033[0m"





def print_human(result):

    if "error" in result:

        print(f"[!] {result['ip']}: {result['error']}")

        return



    band = result["severity"]["band"]

    color = SEVERITY_COLOR.get(band, "")

    print("=" * 60)

    print(f"IP: {result['ip']}")

    print(f"Queried: {result['queried_at_utc']}")

    print(f"Severity: {color}{band}{RESET} (score: {result['severity']['score']}/100)")

    if result["severity"]["reasons"]:

        print("Reasons:")

        for r in result["severity"]["reasons"]:

            print(f"  - {r}")

    else:

        print("Reasons: no risk signals found across configured sources")



    print("\n-- Source Details --")

    for name, src in result["sources"].items():

        if not src.get("configured"):

            print(f"  [{src['source']}] not configured ({src.get('note')})")

        elif not src.get("ok"):

            print(f"  [{src['source']}] query failed: {src.get('error')}")

        else:

            print(f"  [{src['source']}] OK")



    hashes = result["related_iocs"]["hashes"]

    domains = result["related_iocs"]["domains"]



    print(f"\n-- Related Malicious File Hashes ({len(hashes)}) --")

    if hashes:

        for h in hashes:

            hid = h.get("sha256") or h.get("hash")

            print(f"  [{h['source']}] {hid}  (detections: {h.get('malicious_detections', h.get('detections'))})")

    else:

        print("  none found")



    print(f"\n-- Related Domains ({len(domains)}) --")

    if domains:

        for d in domains:

            print(f"  [{d['source']}] {d.get('domain')}")

    else:

        print("  none found")

    print("=" * 60)





# ----------------------------------------------------------------------

# CLI

# ----------------------------------------------------------------------



def main():

    parser = argparse.ArgumentParser(

        description="Look up threat intelligence / IOCs for an IP address."

    )

    parser.add_argument("ip", nargs="?", help="IP address to look up")

    parser.add_argument("--batch", metavar="FILE", help="File with one IP per line")

    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of human-readable text")

    parser.add_argument("--out", metavar="FILE", help="Write JSON output to a file")

    args = parser.parse_args()



    if not args.ip and not args.batch:

        parser.print_help()

        sys.exit(1)



    ips = []

    if args.batch:

        with open(args.batch) as f:

            ips = [line.strip() for line in f if line.strip()]

    else:

        ips = [args.ip]



    if not (ABUSEIPDB_API_KEY or VT_API_KEY or OTX_API_KEY):

        print("[!] Warning: no API keys configured (ABUSEIPDB_API_KEY / VT_API_KEY / OTX_API_KEY).")

        print("    Set at least one environment variable to get real results.\n")



    results = []

    for ip in ips:

        res = lookup_ip(ip)

        results.append(res)

        if not args.json:

            print_human(res)



    if args.json or args.out:

        output = results if len(results) > 1 else results[0]

        text = json.dumps(output, indent=2)

        if args.out:

            with open(args.out, "w") as f:

                f.write(text)

            print(f"[+] JSON written to {args.out}")

        if args.json:

            print(text)





if __name__ == "__main__":

    main()